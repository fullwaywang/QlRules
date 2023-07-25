/**
 * @name imagemagick-30ccf9a0da1f47161b5935a95be854fe84e6c2a2-ReadTIFFImage
 * @id cpp/imagemagick/30ccf9a0da1f47161b5935a95be854fe84e6c2a2/ReadTIFFImage
 * @description imagemagick-30ccf9a0da1f47161b5935a95be854fe84e6c2a2-coders/tiff.c-ReadTIFFImage CVE-2022-3213
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vimage_1200, Variable vsamples_per_pixel_1247, ExprStmt target_4, EqualityOperation target_5, ExprStmt target_6) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_0.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_0.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1200
		and target_0.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_0.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_0.getLeftOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsamples_per_pixel_1247
		and target_0.getLeftOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getRightOperand() instanceof FunctionCall
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsamples_per_pixel_1247, MulExpr target_1) {
		target_1.getLeftOperand().(Literal).getValue()="4"
		and target_1.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsamples_per_pixel_1247
		and target_1.getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_2(Variable vtiff_1229, FunctionCall target_2) {
		target_2.getTarget().hasName("TIFFStripSize")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vtiff_1229
}

predicate func_3(Function func, MulExpr target_3) {
		target_3.getLeftOperand() instanceof MulExpr
		and target_3.getRightOperand() instanceof FunctionCall
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vimage_1200, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("SetImageProgress")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_1200
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Load/Image"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rows"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1200
}

predicate func_5(Variable vimage_1200, EqualityOperation target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vimage_1200
		and target_5.getAnOperand().(Literal).getValue()="0"
}

predicate func_6(Variable vsamples_per_pixel_1247, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsamples_per_pixel_1247
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="5"
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsamples_per_pixel_1247
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(SubExpr).getRightOperand().(Literal).getValue()="5"
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

from Function func, Variable vimage_1200, Variable vtiff_1229, Variable vsamples_per_pixel_1247, MulExpr target_1, FunctionCall target_2, MulExpr target_3, ExprStmt target_4, EqualityOperation target_5, ExprStmt target_6
where
not func_0(vimage_1200, vsamples_per_pixel_1247, target_4, target_5, target_6)
and func_1(vsamples_per_pixel_1247, target_1)
and func_2(vtiff_1229, target_2)
and func_3(func, target_3)
and func_4(vimage_1200, target_4)
and func_5(vimage_1200, target_5)
and func_6(vsamples_per_pixel_1247, target_6)
and vimage_1200.getType().hasName("Image *")
and vtiff_1229.getType().hasName("TIFF *")
and vsamples_per_pixel_1247.getType().hasName("uint16")
and vimage_1200.getParentScope+() = func
and vtiff_1229.getParentScope+() = func
and vsamples_per_pixel_1247.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
