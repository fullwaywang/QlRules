/**
 * @name imagemagick-379e21cd32483df6e128147af3bc4ce1f82eb9c4-ReadTIFFImage
 * @id cpp/imagemagick/379e21cd32483df6e128147af3bc4ce1f82eb9c4/ReadTIFFImage
 * @description imagemagick-379e21cd32483df6e128147af3bc4ce1f82eb9c4-coders/tiff.c-ReadTIFFImage CVE-2017-5508
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vimage_1098, Variable vtiff_1125, Variable vbits_per_sample_1132, Variable vsamples_per_pixel_1143, ExprStmt target_3, EqualityOperation target_4, EqualityOperation target_5, AddExpr target_2, DivExpr target_6, ExprStmt target_7) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand() instanceof FunctionCall
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1098
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vsamples_per_pixel_1143
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("pow")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(Literal).getValue()="2.0"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ceil")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(DivExpr).getLeftOperand().(FunctionCall).getTarget().hasName("log")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(DivExpr).getRightOperand().(FunctionCall).getTarget().hasName("log")
		and target_0.getThen().(FunctionCall).getTarget().hasName("TIFFScanlineSize")
		and target_0.getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_1125
		and target_0.getElse().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getElse().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1098
		and target_0.getElse().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vsamples_per_pixel_1143
		and target_0.getElse().(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("pow")
		and target_0.getElse().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(Literal).getValue()="2.0"
		and target_0.getElse().(MulExpr).getRightOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ceil")
		and target_0.getElse().(MulExpr).getRightOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(DivExpr).getLeftOperand().(FunctionCall).getTarget().hasName("log")
		and target_0.getElse().(MulExpr).getRightOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(DivExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbits_per_sample_1132
		and target_0.getElse().(MulExpr).getRightOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(DivExpr).getRightOperand().(FunctionCall).getTarget().hasName("log")
		and target_0.getElse().(MulExpr).getRightOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(Literal).getValue()="2.0"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireMagickMemory")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof AddExpr
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation())
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getElse().(MulExpr).getRightOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(DivExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtiff_1125, FunctionCall target_1) {
		target_1.getTarget().hasName("TIFFScanlineSize")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vtiff_1125
}

predicate func_2(Function func, AddExpr target_2) {
		target_2.getAnOperand() instanceof FunctionCall
		and target_2.getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireMagickMemory")
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vimage_1098, Variable vtiff_1125, Variable vbits_per_sample_1132, Variable vsamples_per_pixel_1143, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetJPEGMethod")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_1098
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtiff_1125
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbits_per_sample_1132
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsamples_per_pixel_1143
}

predicate func_4(Variable vimage_1098, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vimage_1098
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Variable vtiff_1125, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("TIFFIsTiled")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_1125
}

predicate func_6(Variable vbits_per_sample_1132, DivExpr target_6) {
		target_6.getLeftOperand().(FunctionCall).getTarget().hasName("log")
		and target_6.getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbits_per_sample_1132
		and target_6.getRightOperand().(FunctionCall).getTarget().hasName("log")
		and target_6.getRightOperand().(FunctionCall).getArgument(0).(Literal).getValue()="2"
}

predicate func_7(Variable vsamples_per_pixel_1143, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vsamples_per_pixel_1143
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vsamples_per_pixel_1143
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

from Function func, Variable vimage_1098, Variable vtiff_1125, Variable vbits_per_sample_1132, Variable vsamples_per_pixel_1143, FunctionCall target_1, AddExpr target_2, ExprStmt target_3, EqualityOperation target_4, EqualityOperation target_5, DivExpr target_6, ExprStmt target_7
where
not func_0(vimage_1098, vtiff_1125, vbits_per_sample_1132, vsamples_per_pixel_1143, target_3, target_4, target_5, target_2, target_6, target_7)
and func_1(vtiff_1125, target_1)
and func_2(func, target_2)
and func_3(vimage_1098, vtiff_1125, vbits_per_sample_1132, vsamples_per_pixel_1143, target_3)
and func_4(vimage_1098, target_4)
and func_5(vtiff_1125, target_5)
and func_6(vbits_per_sample_1132, target_6)
and func_7(vsamples_per_pixel_1143, target_7)
and vimage_1098.getType().hasName("Image *")
and vtiff_1125.getType().hasName("TIFF *")
and vbits_per_sample_1132.getType().hasName("uint16")
and vsamples_per_pixel_1143.getType().hasName("uint16")
and vimage_1098.getParentScope+() = func
and vtiff_1125.getParentScope+() = func
and vbits_per_sample_1132.getParentScope+() = func
and vsamples_per_pixel_1143.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
