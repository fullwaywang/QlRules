/**
 * @name openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-atomicio6
 * @id cpp/openssh/8976f1c4b2721c26e878151f52bdf346dfe2d54c/atomicio6
 * @description openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-atomicio.c-atomicio6 CVE-2019-6109
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcb_53, Parameter vcb_arg_53, EqualityOperation target_5, LogicalAndExpr target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcb_53
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableCall).getExpr().(VariableAccess).getTarget()=vcb_53
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vcb_arg_53
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpos_56, VariableAccess target_7, SubExpr target_8, ReturnStmt target_2) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(VariableAccess).getTarget()=vpos_56
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
		and target_8.getRightOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(VariableAccess).getLocation())
		and target_1.getExpr().(VariableAccess).getLocation().isBefore(target_2.getExpr().(VariableAccess).getLocation()))
}

predicate func_2(Variable vpos_56, VariableAccess target_7, ReturnStmt target_2) {
		target_2.getExpr().(VariableAccess).getTarget()=vpos_56
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
}

predicate func_3(Variable vpfd_58, VariableAccess target_7, IfStmt target_3) {
		target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="11"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="11"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("poll")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpfd_58
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

predicate func_6(Parameter vcb_53, Parameter vcb_arg_53, LogicalAndExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcb_53
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableCall).getExpr().(VariableAccess).getTarget()=vcb_53
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vcb_arg_53
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

predicate func_7(Variable vres_57, VariableAccess target_7) {
		target_7.getTarget()=vres_57
}

predicate func_8(Variable vpos_56, SubExpr target_8) {
		target_8.getRightOperand().(VariableAccess).getTarget()=vpos_56
}

from Function func, Parameter vcb_53, Parameter vcb_arg_53, Variable vpos_56, Variable vres_57, Variable vpfd_58, ReturnStmt target_2, IfStmt target_3, ContinueStmt target_4, EqualityOperation target_5, LogicalAndExpr target_6, VariableAccess target_7, SubExpr target_8
where
not func_0(vcb_53, vcb_arg_53, target_5, target_6)
and not func_1(vpos_56, target_7, target_8, target_2)
and func_2(vpos_56, target_7, target_2)
and func_3(vpfd_58, target_7, target_3)
and func_4(target_5, func, target_4)
and func_5(target_5)
and func_6(vcb_53, vcb_arg_53, target_6)
and func_7(vres_57, target_7)
and func_8(vpos_56, target_8)
and vcb_53.getType().hasName("..(*)(..)")
and vcb_arg_53.getType().hasName("void *")
and vpos_56.getType().hasName("size_t")
and vres_57.getType().hasName("ssize_t")
and vpfd_58.getType().hasName("pollfd")
and vcb_53.getParentScope+() = func
and vcb_arg_53.getParentScope+() = func
and vpos_56.getParentScope+() = func
and vres_57.getParentScope+() = func
and vpfd_58.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
