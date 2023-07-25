/**
 * @name openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-atomiciov6
 * @id cpp/openssh/8976f1c4b2721c26e878151f52bdf346dfe2d54c/atomiciov6
 * @description openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-atomicio.c-atomiciov6 CVE-2019-6109
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcb_103, Parameter vcb_arg_103, EqualityOperation target_5, LogicalAndExpr target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcb_103
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableCall).getExpr().(VariableAccess).getTarget()=vcb_103
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vcb_arg_103
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpos_105, VariableAccess target_7, ReturnStmt target_2) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(VariableAccess).getTarget()=vpos_105
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
		and target_1.getExpr().(VariableAccess).getLocation().isBefore(target_2.getExpr().(VariableAccess).getLocation()))
}

predicate func_2(Variable vpos_105, VariableAccess target_7, ReturnStmt target_2) {
		target_2.getExpr().(VariableAccess).getTarget()=vpos_105
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
}

predicate func_3(Variable vpfd_108, VariableAccess target_7, IfStmt target_3) {
		target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="11"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="11"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("poll")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpfd_108
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_3.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
}

predicate func_4(EqualityOperation target_5, Function func, ContinueStmt target_4) {
		target_4.toString() = "continue;"
		and target_4.getParent().(IfStmt).getCondition()=target_5
		and target_4.getEnclosingFunction() = func
}

predicate func_5(EqualityOperation target_5) {
		target_5.getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_5.getAnOperand().(Literal).getValue()="4"
}

predicate func_6(Parameter vcb_103, Parameter vcb_arg_103, LogicalAndExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcb_103
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableCall).getExpr().(VariableAccess).getTarget()=vcb_103
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vcb_arg_103
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

predicate func_7(Variable vres_106, VariableAccess target_7) {
		target_7.getTarget()=vres_106
}

from Function func, Parameter vcb_103, Parameter vcb_arg_103, Variable vpos_105, Variable vres_106, Variable vpfd_108, ReturnStmt target_2, IfStmt target_3, ContinueStmt target_4, EqualityOperation target_5, LogicalAndExpr target_6, VariableAccess target_7
where
not func_0(vcb_103, vcb_arg_103, target_5, target_6)
and not func_1(vpos_105, target_7, target_2)
and func_2(vpos_105, target_7, target_2)
and func_3(vpfd_108, target_7, target_3)
and func_4(target_5, func, target_4)
and func_5(target_5)
and func_6(vcb_103, vcb_arg_103, target_6)
and func_7(vres_106, target_7)
and vcb_103.getType().hasName("..(*)(..)")
and vcb_arg_103.getType().hasName("void *")
and vpos_105.getType().hasName("size_t")
and vres_106.getType().hasName("ssize_t")
and vpfd_108.getType().hasName("pollfd")
and vcb_103.getParentScope+() = func
and vcb_arg_103.getParentScope+() = func
and vpos_105.getParentScope+() = func
and vres_106.getParentScope+() = func
and vpfd_108.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
