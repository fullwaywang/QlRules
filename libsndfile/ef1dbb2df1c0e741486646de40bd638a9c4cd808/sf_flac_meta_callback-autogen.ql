/**
 * @name libsndfile-ef1dbb2df1c0e741486646de40bd638a9c4cd808-sf_flac_meta_callback
 * @id cpp/libsndfile/ef1dbb2df1c0e741486646de40bd638a9c4cd808/sf-flac-meta-callback
 * @description libsndfile-ef1dbb2df1c0e741486646de40bd638a9c4cd808-src/flac.c-sf_flac_meta_callback CVE-2017-8362
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="Error: FLAC stream changed from %d to %d channels\nNothing to be but to error out.\n"
		and not target_0.getValue()="Error: FLAC stream changed from %d to %d channels\nNothing to do but to error out.\n"
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
