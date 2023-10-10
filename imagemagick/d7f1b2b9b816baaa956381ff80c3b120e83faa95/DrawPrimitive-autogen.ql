/**
 * @name imagemagick-d7f1b2b9b816baaa956381ff80c3b120e83faa95-DrawPrimitive
 * @id cpp/imagemagick/d7f1b2b9b816baaa956381ff80c3b120e83faa95/DrawPrimitive
 * @description imagemagick-d7f1b2b9b816baaa956381ff80c3b120e83faa95-MagickCore/draw.c-DrawPrimitive CVE-2021-4219
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignAndExpr).getRValue().(FunctionCall).getTarget().hasName("SetImageInfo")
		and target_0.getEnclosingFunction() = func
}

from Function func, Literal target_0
where
func_0(func, target_0)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
