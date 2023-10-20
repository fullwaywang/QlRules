/**
 * @name vim-35a9a00afcb20897d462a766793ff45534810dc3-nv_replace
 * @id cpp/vim/35a9a00afcb20897d462a766793ff45534810dc3/nv-replace
 * @description vim-35a9a00afcb20897d462a766793ff45534810dc3-src/normal.c-nv_replace CVE-2021-3796
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vptr_4942, Variable vcurbuf, Variable vcurwin, LogicalOrExpr target_3, ExprStmt target_4, ExprStmt target_2, ExprStmt target_1, ExprStmt target_5) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_4942
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ml_get_buf")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcurbuf
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="lnum"
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vptr_4942, Variable vcurbuf, Variable vcurwin, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_4942
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ml_get_buf")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcurbuf
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="lnum"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

predicate func_2(Parameter vcap_4940, Variable vptr_4942, Variable vcurwin, LogicalOrExpr target_3, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vptr_4942
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getTarget().getName()="col"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="nchar"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_4940
		and target_2.getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Parameter vcap_4940, LogicalOrExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nchar"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_4940
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="5"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nchar"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_4940
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="25"
}

predicate func_4(Variable vptr_4942, Variable vcurwin, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vptr_4942
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getTarget().getName()="col"
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
}

predicate func_5(Parameter vcap_4940, Variable vcurbuf, Variable vcurwin, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("netbeans_removed")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcurbuf
		and target_5.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="lnum"
		and target_5.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_5.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_5.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="count1"
		and target_5.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_4940
}

from Function func, Parameter vcap_4940, Variable vptr_4942, Variable vcurbuf, Variable vcurwin, ExprStmt target_1, ExprStmt target_2, LogicalOrExpr target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vptr_4942, vcurbuf, vcurwin, target_3, target_4, target_2, target_1, target_5)
and func_1(vptr_4942, vcurbuf, vcurwin, target_1)
and func_2(vcap_4940, vptr_4942, vcurwin, target_3, target_2)
and func_3(vcap_4940, target_3)
and func_4(vptr_4942, vcurwin, target_4)
and func_5(vcap_4940, vcurbuf, vcurwin, target_5)
and vcap_4940.getType().hasName("cmdarg_T *")
and vptr_4942.getType().hasName("char_u *")
and vcurbuf.getType().hasName("buf_T *")
and vcurwin.getType().hasName("win_T *")
and vcap_4940.getParentScope+() = func
and vptr_4942.getParentScope+() = func
and not vcurbuf.getParentScope+() = func
and not vcurwin.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
