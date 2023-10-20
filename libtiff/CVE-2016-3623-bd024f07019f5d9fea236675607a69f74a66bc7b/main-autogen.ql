/**
 * @name libtiff-bd024f07019f5d9fea236675607a69f74a66bc7b-main
 * @id cpp/libtiff/bd024f07019f5d9fea236675607a69f74a66bc7b/main
 * @description libtiff-bd024f07019f5d9fea236675607a69f74a66bc7b-tools/rgb2ycbcr.c-main CVE-2016-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vhorizSubSampling, VariableAccess target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhorizSubSampling
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhorizSubSampling
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhorizSubSampling
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("usage")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vvertSubSampling, VariableAccess target_2, ExprStmt target_4) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvertSubSampling
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvertSubSampling
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvertSubSampling
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("usage")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_2
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vc_74, VariableAccess target_2) {
		target_2.getTarget()=vc_74
}

predicate func_3(Variable vhorizSubSampling, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhorizSubSampling
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("atoi")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
}

predicate func_4(Variable vvertSubSampling, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvertSubSampling
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("atoi")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
}

from Function func, Variable vc_74, Variable vhorizSubSampling, Variable vvertSubSampling, VariableAccess target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vhorizSubSampling, target_2, target_3)
and not func_1(vvertSubSampling, target_2, target_4)
and func_2(vc_74, target_2)
and func_3(vhorizSubSampling, target_3)
and func_4(vvertSubSampling, target_4)
and vc_74.getType().hasName("int")
and vhorizSubSampling.getType().hasName("uint16")
and vvertSubSampling.getType().hasName("uint16")
and vc_74.(LocalVariable).getFunction() = func
and not vhorizSubSampling.getParentScope+() = func
and not vvertSubSampling.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
