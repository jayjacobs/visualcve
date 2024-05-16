suppressPackageStartupMessages({
  library(gh)
  library(dplyr)
  library(httr)
  library(here)
  library(log4r)
  library(lubridate)
  library(purrr)
  library(arrow)
  library(tidyjson)
})
repo <- "CVEProject/cvelistV5"

# create a temp directory if it doesn't exist.
exdir <- here("cache", "cvelist")
if(dir.exists(exdir)) {
  unlink(exdir, recursive = TRUE, expand=FALSE)
}
dir.create(exdir, mode = "0755", recursive=TRUE)

# going to log this into a new log file
# just in case we want to double check on a CVE
curlog <- log4r::logger(threshold = "DEBUG",
                        appenders = list(
                          log4r::file_appender(file=here("cache", "cve_parsing.log"), append = FALSE),
                          log4r::console_appender()))

# grab base repo infor
repo_info <- gh(paste0("/repos/", repo))

# create path for tarball of whole repository
path <- paste0("/repos/CVEProject/cvelistV5/tarball/", repo_info$default_branch)
log4r::debug(curlog, paste("Retrieving", path))
url <- httr::modify_url("https://api.github.com", path = path)

# set up a local temp file to download to
tmpfile <- here("cache", paste0("cvelist-", Sys.Date(), ".tar.gz"))
ignored_resp <- httr::GET(url, httr::write_disk(tmpfile, overwrite=TRUE))

log4r::debug(curlog, "Unbundling the CVE List files")

# pull out all the things
untar(tmpfile, exdir = exdir)

# get a list of the CVE json files
jsonfiles <- list.files(exdir, recursive = TRUE, pattern="CVE.*json", full.name=TRUE)

log4r::debug(curlog, paste("Found", length(jsonfiles), "JSON files, reading them in..."))

# read them in while you go make a sandwich
alljson <- map_dfr(jsonfiles, read_json) %>%
  mutate(document.id = row_number())

log4r::debug(curlog, paste("Cleaning up the CVE Files..."))
# cleanup our mess.
unlink(exdir, recursive = TRUE, expand=FALSE)
unlink(tmpfile)

# this function does recursion
jparse <- function(json, curkey = NA, datakey = "toplevel", datastore = NULL) {
  log4r::debug(curlog, paste("        : >>", curkey))
  mykey <- ifelse(!is.na(curkey), paste0(curkey, "."), "")
  # the name of the data store we are working in
  if(is.null(datastore)) {
    log4r::debug(curlog, paste("Setting up backend datastore"))
    datastore <- list(json %>% as_tibble())
    names(datastore) <- datakey
  } else {
    if(!datakey %in% names(datastore)) {
      to_append <- list(json %>% as_tibble())
      names(to_append) <- datakey
      datastore <- append(datastore, to_append)
      # cat("appending", datakey, ":", paste(names(datastore), collapse=","), "\n")
    }
  }
  curtypes <- tibble()
  try({
    curtypes <- json %>%
      gather_object() %>%
      json_types() %>%
      count(name, type)
  })
  if(nrow(curtypes) == 0) {
    # checking for array of strings only...
    curstring <- json %>%
      append_values_string(curkey) %>%
      as_tibble()
    if(any(!is.na(curstring[[curkey]]))) { # we have values
      log4r::debug(curlog, paste(curkey, ": found array of strings"))

      datastore[[datakey]] <- datastore[[datakey]] %>%
        left_join(curstring)
      return(datastore) # there is nothing else here.
    } else {
      log4r::warn(curlog, paste("array of string parsing failed:", curkey))
      # log4r::warn(curlog, paste("No valid json found", curkey))
    }
    return(datastore)
  } else {
    varlist <- curtypes %>%
      summarize(.by=c(name,n), type = paste(sort(type), collapse=", ")) %>%
      mutate(name = paste0(mykey, name)) %>%
      arrange(name)
    if(!"variables" %in% names(datastore)) {
      datastore[['variables']] <- tibble(name=character(), n=integer(), type=character())
    }
    datastore[['variables']] <- datastore[['variables']] %>%
      bind_rows(varlist) %>%
      arrange(name)

  }

  errcheck <- curtypes %>%
    mutate(.by=name, name_count=n()) %>%
    filter(name_count > 1) %>%
    summarize(.by=name, type = paste(sort(type), collapse=", ")) %>%
    mutate(name = paste0(mykey, name))
  if(nrow(errcheck) > 0) {
    for(x in seq(nrow(errcheck))) {
      log4r::error(curlog, paste("Multiple data types:", errcheck$name[x], ":", errcheck$type[x]))
    }
    # return(datastore)
  }

  # Handle Strings
  if(any(c("number", "string") %in% curtypes$type)) {
    newcols <- curtypes %>%
      filter(type %in% c("number", "string")) %>%
      select(name) %>%
      distinct() %>%
      pull(name)
    names(newcols) <- paste0(mykey, newcols)
    curstring <- tibble()
    try({
      curstring <- json %>%
        spread_all(recursive = FALSE) %>%
        rename(any_of(newcols)) %>%
        as_tibble()
    })
    if((ncol(curstring) > 1) & (nrow(curstring) > 0)) {
      datastore[[datakey]] <- datastore[[datakey]] %>%
        left_join(curstring)
    } else {
      log4r::warn(curlog, paste("string parsing failed:", curkey))

    }
  }
  # handle objects in the current level
  if("object" %in% curtypes$type) {
    object_stuff <- curtypes %>% filter(type == "object")
    for (i in seq(nrow(object_stuff))) {
      curname <- object_stuff$name[i]
      log4r::warn(curlog, paste("  object curname: ", curname))
      newkey <- paste0(mykey, curname)
      if(newkey %in% errcheck$name) {
        log4r::warn(curlog, paste("Skipping: ", newkey))
      } else if (grepl("^x_", curname)) {
        log4r::warn(curlog, paste("Skipping x_ name: ", newkey))
      } else {
        log4r::debug(curlog, paste("  Object: ", newkey))
        datastore <- jparse(json %>% enter_object({{ curname }}), curkey = newkey,
                            datakey=datakey, datastore=datastore)
      }
    }
  }
  # grab arrays
  if("array" %in% curtypes$type) {
    array_stuff <- curtypes %>% filter(type == "array")
    for (i in seq(nrow(array_stuff))) {
      curname <- array_stuff$name[i]
      newkey <- paste0(mykey, curname)
      log4r::warn(curlog, paste("  array curname: ", curname))
      if(newkey %in% errcheck$name) {
        log4r::warn(curlog, paste("Skipping: ", newkey))
      } else if (grepl("^x_", curname)) {
        log4r::warn(curlog, paste("Skipping x_ name: ", newkey))
      } else {
        log4r::debug(curlog, paste("  Array : ", newkey))
        passing_on <- json %>%
          enter_object({{ curname }}) %>%
          gather_array(paste0(curname, "_id"))
        datastore <- jparse(passing_on, curkey = newkey,
                            datakey=newkey, datastore=datastore)
      }
    }
  }
  datastore
}

# Because I like to know just how painful JSON is in R
# I will set up a timer and remind myself every time this runs.
starttime <- proc.time()
cleanjson <- jparse(alljson)
log4r::debug(curlog, paste("completed parsing of the JSON:", length(cleanjson), "records found."))
outfiles <- names(cleanjson)
validcve <- cleanjson[['toplevel']] %>%
  select(document.id, cve=cveMetadata.cveId)

if(!dir.exists(here("cache", "cveparse"))) {
  log4r::debug(curlog, paste("creating", here("cache", "cveparse")))
  dir.create(here("cache", "cveparse"), mode = "0755")
}

for (curfile in outfiles) {
  outfile <- here("cache", "cveparse", paste0(ifelse(curfile == "toplevel", "cves", curfile), ".parquet"))
  if(curfile == "variables") {
    write_parquet(cleanjson[[curfile]], sink = outfile)
  } else {
    outdf <- cleanjson[[curfile]] %>%
      inner_join(validcve, by="document.id") %>%
      select(-any_of(c("document.id"))) %>%
      relocate(cve)
    write_parquet(outdf, sink = outfile)
  }
}
log4r::info(curlog, "completed")

totaldur <- round(as.vector((proc.time() - starttime)[3]), 2)
log4r::info(curlog, paste("Time to parse:", as.character(lubridate::duration(totaldur))))

