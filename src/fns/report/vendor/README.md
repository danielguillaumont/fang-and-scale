# Vendored files

| File | Version | Licence | Source | Hash |
| --- | --- | --- | --- | --- |
| `cytoscape-3.30.2.min.js` | Cytoscape.js 3.30.2 | MIT, `cytoscape-3.30.2.LICENSE` (the notice is also the file's header) | `https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js` | `sha384-IWROdLKRsN1UuJywMlWl7/blXQ8GEooN2n7dzTxfEPd7ybYIKCUJ2Ol/1Gpf3YV4` (the published SRI hash) |

`fns report` embeds the file in every HTML report, so the report needs no network
access. `fns.report.html.cytoscape_js()` refuses to embed it unless its SHA-384
matches the hash above, and `tests/test_report_html.py` checks the same.

The files are kept byte for byte as downloaded: `.gitattributes` marks them
`-text`, and the pre-commit whitespace hooks skip this directory.

To update: download the new version from cdnjs, check its published SRI hash,
and change the version, file names and `CYTOSCAPE_SRI` in `html.py` together.
