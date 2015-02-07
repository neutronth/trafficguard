#include <thread>
#include <memory>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <string>

#include "Blacklist.h"

using namespace TrafficGuard;
using std::thread;
using std::make_shared;
using std::ifstream;
using std::string;
using std::getline;
using std::size_t;

namespace TrafficGuard
{

Blacklist::Blacklist (string base_path, atomic<bool> *ready)
  : base_path_ (base_path), ready_ (ready)
{
  LoadPatterns ();
}

void
Blacklist::LoadPatterns ()
{
  *ready_ = false;
  thread t(&Blacklist::ReloadPatterns, this);
  t.detach ();
}

void
Blacklist::ReloadPatterns ()
{
  categories_.clear ();

  DIR *dir = opendir (base_path_.c_str ());
  if (!dir)
    {
      tg_log.logError ("Blacklist base path: %s does not exist!",
                       base_path_.c_str ());
    }

  struct dirent *ent = NULL;
  while ((ent = readdir (dir)))
    {
      if (strcmp (ent->d_name, ".") != 0 && strcmp (ent->d_name, "..") != 0)
        {
          auto BlCat = make_shared<BlacklistCategory> (ent->d_name, base_path_);

          if (BlCat->isValid ())
            categories_.push_back (BlCat);
        }
    }

  closedir (dir);

  if (categories_.size () > 0)
    {
      tg_log.logInfo ("Blacklist activated");
      *ready_ = true;
    }
  else
    {
      tg_log.logInfo ("!!! No blacklist activated !!!");
    }
}

bool
Blacklist::Match (string domain, string url, string &ret_category)
{
  for (auto cat : categories_)
    {
      if (cat->DomainMatch (domain))
        {
          ret_category.assign (cat->getName ());
          return true;
        }

      if (cat->UrlMatch (url))
        {
          ret_category.assign (cat->getName ());
          return true;
        }
    }

  return false;
}

bool
BlacklistCategory::Match (vector<shared_ptr<RE>> &storage, string text)
{
  for (auto re : storage)
    {
      if (re->FullMatch (text))
        return true;
    }

  return false;
}


bool
BlacklistCategory::DomainMatch (string text)
{
  return Match (domains_set_, text);
}

bool
BlacklistCategory::UrlMatch (string text)
{
  if (text.find ("http://") == 0)
    return Match (urls_set_, text.substr (7, text.size ()));
  else
    return Match (urls_set_, text);
}

void
BlacklistCategory::LoadPatterns (string type)
{
  string path (base_path_); 
  path.append ("/");
  path.append (name_);
  path.append ("/");
  path.append (type);

  tg_log.logInfo ("Processing Category: %s, Path: %s", name_.c_str (),
                  path.c_str ());

  ifstream patterns (path);

  if (patterns.is_open ())
    {
      string regex_patterns ("");
      string line;
      int    count = 0;
      while (getline (patterns, line))
        {
          regex_patterns.append ("(");
          regex_patterns.append (line);
          regex_patterns.append (")|");

          if ((++count % 1000) == 0)
            {
              ProcessPatterns (type, regex_patterns);
              count = 0;
              regex_patterns.clear ();
            }
        }

      if (regex_patterns.size () > 0)
        {
          ProcessPatterns (type, regex_patterns);
        }
    }
}

void
BlacklistCategory::ProcessPatterns (string type, string &patterns)
{
  auto re = make_shared<RE> (patterns, pcre_opts_);

  if (re)
    {
      if (re->error ().size () == 0)
        {
          StorePatterns (type, re);
        }
      else if (re->error ().find ("too large") != string::npos)
        {
          size_t half = patterns.find ("|", patterns.size () / 2);
          string patterns_first = patterns.substr (0, half);
          string patterns_second = patterns.substr (half + 1, patterns.size ());

          ProcessPatterns (type, patterns_first);
          ProcessPatterns (type, patterns_second);
        }
      else
        {
          tg_log.logError ("Category: %s, Type: %s, Error: %s, Patterns: %s...",
                           name_.c_str (), type.c_str (), re->error ().c_str (),
                           (patterns.substr (0, 160)).c_str ());
        }
    }
}

void
BlacklistCategory::StorePatterns (string type, shared_ptr<RE> re)
{
  if (type.find ("domains") != string::npos)
    {
      domains_set_.push_back (re);
    }
  else if (type.find ("urls") != string::npos)
    {
      urls_set_.push_back (re);
    }
}

void
BlacklistCategory::LoadDomains ()
{
  LoadPatterns ("domains");
}

void
BlacklistCategory::LoadUrls ()
{
  LoadPatterns ("urls");
}

} /* TrafficGuard namespace */
