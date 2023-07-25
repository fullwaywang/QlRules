/**
 * @name vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-vterm_new_with_allocator
 * @id cpp/vim/cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8/vterm-new-with-allocator
 * @description vim-cd929f7ba8cc5b6d6dcf35c8b34124e969fed6b8-src/libvterm/src/vterm.c-vterm_new_with_allocator CVE-2018-20786
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vvt_42, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvt_42
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vvt_42, ValueFieldAccess target_4, ExprStmt target_5, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="strbuffer"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parser"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvt_42
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vterm_allocator_free")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvt_42
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvt_42
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_1)
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vvt_42, ExprStmt target_6, ReturnStmt target_7, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="outbuffer"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvt_42
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vterm_allocator_free")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvt_42
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="strbuffer"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parser"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvt_42
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vterm_allocator_free")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvt_42
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvt_42
		and target_2.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_2)
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(VariableAccess).getLocation()))
}

predicate func_3(Variable vvt_42, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="allocator"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvt_42
}

predicate func_4(Variable vvt_42, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="strbuffer_len"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="parser"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvt_42
}

predicate func_5(Variable vvt_42, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="outbuffer_len"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvt_42
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="200"
}

predicate func_6(Variable vvt_42, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="outbuffer"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvt_42
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vterm_allocator_malloc")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvt_42
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="outbuffer_len"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvt_42
}

predicate func_7(Variable vvt_42, ReturnStmt target_7) {
		target_7.getExpr().(VariableAccess).getTarget()=vvt_42
}

from Function func, Variable vvt_42, ExprStmt target_3, ValueFieldAccess target_4, ExprStmt target_5, ExprStmt target_6, ReturnStmt target_7
where
not func_0(vvt_42, target_3, func)
and not func_1(vvt_42, target_4, target_5, func)
and not func_2(vvt_42, target_6, target_7, func)
and func_3(vvt_42, target_3)
and func_4(vvt_42, target_4)
and func_5(vvt_42, target_5)
and func_6(vvt_42, target_6)
and func_7(vvt_42, target_7)
and vvt_42.getType().hasName("VTerm *")
and vvt_42.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
