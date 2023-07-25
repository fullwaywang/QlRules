/**
 * @name openjpeg-e5285319229a5d77bf316bb0d3a6cbd3cb8666d9-pgxtoimage
 * @id cpp/openjpeg/e5285319229a5d77bf316bb0d3a6cbd3cb8666d9/pgxtoimage
 * @description openjpeg-e5285319229a5d77bf316bb0d3a6cbd3cb8666d9-src/bin/jp2/convert.c-pgxtoimage CVE-2017-14041
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="PG%[ \t]%c%c%[ \t+-]%d%[ \t]%d%[ \t]%d"
		and not target_0.getValue()="PG%31[ \t]%c%c%31[ \t+-]%d%31[ \t]%d%31[ \t]%d"
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
