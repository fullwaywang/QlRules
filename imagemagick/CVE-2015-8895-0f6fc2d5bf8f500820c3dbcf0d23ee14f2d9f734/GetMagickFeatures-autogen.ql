/**
 * @name imagemagick-0f6fc2d5bf8f500820c3dbcf0d23ee14f2d9f734-GetMagickFeatures
 * @id cpp/imagemagick/0f6fc2d5bf8f500820c3dbcf0d23ee14f2d9f734/GetMagickFeatures
 * @description imagemagick-0f6fc2d5bf8f500820c3dbcf0d23ee14f2d9f734-MagickCore/version.c-GetMagickFeatures CVE-2015-8895
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="DPC HDRI OpenMP"
		and not target_0.getValue()="DPC Cipher HDRI OpenMP"
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
