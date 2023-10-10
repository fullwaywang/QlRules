/**
 * @name imagemagick-eac8ce4d873f28bb6a46aa3a662fb196b49b95d0-GetEXIFProperty
 * @id cpp/imagemagick/eac8ce4d873f28bb6a46aa3a662fb196b49b95d0/GetEXIFProperty
 * @description imagemagick-eac8ce4d873f28bb6a46aa3a662fb196b49b95d0-MagickCore/property.c-GetEXIFProperty CVE-2022-32547
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp1_1548, Variable vendian_1237, ExprStmt target_6, FunctionCall target_7) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ReadPropertySignedLong")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vendian_1237
		and target_0.getArgument(1).(VariableAccess).getTarget()=vp1_1548
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation())
		and target_7.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vp1_1553, Variable vendian_1237, ExprStmt target_8, ExprStmt target_9) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("ReadPropertySignedLong")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vendian_1237
		and target_1.getArgument(1).(VariableAccess).getTarget()=vp1_1553
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getArgument(1).(VariableAccess).getLocation())
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vp1_1548, VariableAccess target_2) {
		target_2.getTarget()=vp1_1548
}

predicate func_3(Variable vp1_1553, VariableAccess target_3) {
		target_3.getTarget()=vp1_1553
}

predicate func_4(Variable vp1_1548, PointerDereferenceExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vp1_1548
		and target_4.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("FormatLocaleString")
		and target_4.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(Literal).getValue()="4096"
		and target_4.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%f, "
}

predicate func_5(Variable vp1_1553, PointerDereferenceExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vp1_1553
		and target_5.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("FormatLocaleString")
		and target_5.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(Literal).getValue()="4096"
		and target_5.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%f, "
}

predicate func_6(Variable vp1_1548, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp1_1548
}

predicate func_7(Variable vendian_1237, FunctionCall target_7) {
		target_7.getTarget().hasName("ReadPropertySignedLong")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vendian_1237
		and target_7.getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="4"
}

predicate func_8(Variable vp1_1553, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp1_1553
}

predicate func_9(Variable vendian_1237, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadPropertySignedLong")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vendian_1237
}

from Function func, Variable vp1_1548, Variable vp1_1553, Variable vendian_1237, VariableAccess target_2, VariableAccess target_3, PointerDereferenceExpr target_4, PointerDereferenceExpr target_5, ExprStmt target_6, FunctionCall target_7, ExprStmt target_8, ExprStmt target_9
where
not func_0(vp1_1548, vendian_1237, target_6, target_7)
and not func_1(vp1_1553, vendian_1237, target_8, target_9)
and func_2(vp1_1548, target_2)
and func_3(vp1_1553, target_3)
and func_4(vp1_1548, target_4)
and func_5(vp1_1553, target_5)
and func_6(vp1_1548, target_6)
and func_7(vendian_1237, target_7)
and func_8(vp1_1553, target_8)
and func_9(vendian_1237, target_9)
and vp1_1548.getType().hasName("unsigned char *")
and vp1_1553.getType().hasName("unsigned char *")
and vendian_1237.getType().hasName("EndianType")
and vp1_1548.getParentScope+() = func
and vp1_1553.getParentScope+() = func
and vendian_1237.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
