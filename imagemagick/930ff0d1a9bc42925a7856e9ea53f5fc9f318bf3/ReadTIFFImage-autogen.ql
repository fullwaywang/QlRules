/**
 * @name imagemagick-930ff0d1a9bc42925a7856e9ea53f5fc9f318bf3-ReadTIFFImage
 * @id cpp/imagemagick/930ff0d1a9bc42925a7856e9ea53f5fc9f318bf3/ReadTIFFImage
 * @description imagemagick-930ff0d1a9bc42925a7856e9ea53f5fc9f318bf3-coders/tiff.c-ReadTIFFImage CVE-2021-3610
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="4"
		and target_0.getParent().(MulExpr).getParent().(AssignExpr).getRValue().(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("TIFFStripSize")
		and target_0.getEnclosingFunction() = func
}

from Function func, Literal target_0
where
func_0(func, target_0)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
