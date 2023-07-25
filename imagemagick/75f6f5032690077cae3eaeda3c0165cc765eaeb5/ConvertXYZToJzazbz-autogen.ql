/**
 * @name imagemagick-75f6f5032690077cae3eaeda3c0165cc765eaeb5-ConvertXYZToJzazbz
 * @id cpp/imagemagick/75f6f5032690077cae3eaeda3c0165cc765eaeb5/ConvertXYZToJzazbz
 * @description imagemagick-75f6f5032690077cae3eaeda3c0165cc765eaeb5-MagickCore/colorspace.c-ConvertXYZToJzazbz CVE-2021-20310
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vwhite_luminance_301, Variable vL_316, DivExpr target_10, ExprStmt target_12) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vL_316
		and target_0.getRightOperand().(FunctionCall).getTarget().hasName("PerceptibleReciprocal")
		and target_0.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwhite_luminance_301
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pow")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof DivExpr
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(DivExpr).getValue()="0.1593017578125"
		and target_0.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getRightOperand().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vwhite_luminance_301, Variable vM_318, DivExpr target_9, DivExpr target_11, ExprStmt target_13) {
	exists(MulExpr target_1 |
		target_1.getLeftOperand().(VariableAccess).getTarget()=vM_318
		and target_1.getRightOperand().(FunctionCall).getTarget().hasName("PerceptibleReciprocal")
		and target_1.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwhite_luminance_301
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pow")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof DivExpr
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(DivExpr).getValue()="0.1593017578125"
		and target_9.getRightOperand().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getRightOperand().(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vwhite_luminance_301, Variable vS_320, DivExpr target_10, ExprStmt target_14) {
	exists(MulExpr target_2 |
		target_2.getLeftOperand().(VariableAccess).getTarget()=vS_320
		and target_2.getRightOperand().(FunctionCall).getTarget().hasName("PerceptibleReciprocal")
		and target_2.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwhite_luminance_301
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pow")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof DivExpr
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(DivExpr).getValue()="0.1593017578125"
		and target_10.getRightOperand().(VariableAccess).getLocation().isBefore(target_2.getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vL_316, VariableAccess target_3) {
		target_3.getTarget()=vL_316
}

predicate func_4(Variable vM_318, VariableAccess target_4) {
		target_4.getTarget()=vM_318
}

predicate func_5(Variable vS_320, VariableAccess target_5) {
		target_5.getTarget()=vS_320
}

predicate func_6(Parameter vwhite_luminance_301, VariableAccess target_6) {
		target_6.getTarget()=vwhite_luminance_301
}

predicate func_7(Parameter vwhite_luminance_301, VariableAccess target_7) {
		target_7.getTarget()=vwhite_luminance_301
}

predicate func_8(Parameter vwhite_luminance_301, VariableAccess target_8) {
		target_8.getTarget()=vwhite_luminance_301
}

predicate func_9(Parameter vwhite_luminance_301, Variable vL_316, DivExpr target_9) {
		target_9.getLeftOperand().(VariableAccess).getTarget()=vL_316
		and target_9.getRightOperand().(VariableAccess).getTarget()=vwhite_luminance_301
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pow")
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(DivExpr).getValue()="0.1593017578125"
}

predicate func_10(Parameter vwhite_luminance_301, Variable vM_318, DivExpr target_10) {
		target_10.getLeftOperand().(VariableAccess).getTarget()=vM_318
		and target_10.getRightOperand().(VariableAccess).getTarget()=vwhite_luminance_301
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pow")
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(DivExpr).getValue()="0.1593017578125"
}

predicate func_11(Parameter vwhite_luminance_301, Variable vS_320, DivExpr target_11) {
		target_11.getLeftOperand().(VariableAccess).getTarget()=vS_320
		and target_11.getRightOperand().(VariableAccess).getTarget()=vwhite_luminance_301
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pow")
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(DivExpr).getValue()="0.1593017578125"
}

predicate func_12(Variable vL_316, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vL_316
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="0.4147897199999999729"
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="0.5799990000000000423"
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="0.01464799999999999956"
}

predicate func_13(Variable vM_318, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vM_318
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(UnaryMinusExpr).getValue()="-0.2015099999999999947"
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="1.120649000000000006"
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="0.05310079999999999661"
}

predicate func_14(Variable vS_320, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vS_320
		and target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(UnaryMinusExpr).getValue()="-0.01660079999999999889"
		and target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="0.2647999999999999798"
		and target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="0.6684799000000000158"
}

from Function func, Parameter vwhite_luminance_301, Variable vL_316, Variable vM_318, Variable vS_320, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, VariableAccess target_8, DivExpr target_9, DivExpr target_10, DivExpr target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14
where
not func_0(vwhite_luminance_301, vL_316, target_10, target_12)
and not func_1(vwhite_luminance_301, vM_318, target_9, target_11, target_13)
and not func_2(vwhite_luminance_301, vS_320, target_10, target_14)
and func_3(vL_316, target_3)
and func_4(vM_318, target_4)
and func_5(vS_320, target_5)
and func_6(vwhite_luminance_301, target_6)
and func_7(vwhite_luminance_301, target_7)
and func_8(vwhite_luminance_301, target_8)
and func_9(vwhite_luminance_301, vL_316, target_9)
and func_10(vwhite_luminance_301, vM_318, target_10)
and func_11(vwhite_luminance_301, vS_320, target_11)
and func_12(vL_316, target_12)
and func_13(vM_318, target_13)
and func_14(vS_320, target_14)
and vwhite_luminance_301.getType().hasName("const double")
and vL_316.getType().hasName("double")
and vM_318.getType().hasName("double")
and vS_320.getType().hasName("double")
and vwhite_luminance_301.getParentScope+() = func
and vL_316.getParentScope+() = func
and vM_318.getParentScope+() = func
and vS_320.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
