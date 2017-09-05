## What is this?

A nginx module to serve map tiles directly from mbtiles container files.

## Nginx configuration example

* mbtiles_file - points to the mbtiles file

<pre>
  location ~ ^/(.*?)/(.*?)/(.*?)/(.*?)$ {
      mbtiles_file "$document_root/$1.mbtiles";
      mbtiles_zoom "$2";
      mbtiles_column "$3";
      mbtiles_row "$4";
  }

</pre>

## Installation

### Prerequisits

You need to have a `sqlite3-dev` package installed. On Ubuntu or Debian you can install it using:

```sh
apt-get install libsqlite3-dev
```