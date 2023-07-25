/**
 * @name ghostscript-b575e1ec42cc86f6a58c603f2a88fcc2af699cc8-gs_call_interp
 * @id cpp/ghostscript/b575e1ec42cc86f6a58c603f2a88fcc2af699cc8/gs-call-interp
 * @description ghostscript-b575e1ec42cc86f6a58c603f2a88fcc2af699cc8-psi/interp.c-gs_call_interp CVE-2018-16542
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(PostfixIncrExpr target_0 |
		target_0.getOperand() instanceof ValueFieldAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vpexit_code_484, Variable vi_ctx_p_492, NotExpr target_6, ExprStmt target_7, ValueFieldAccess target_8, ExprStmt target_9) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="p"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_492
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_492
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpexit_code_484
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vperror_object_484, Variable vi_ctx_p_492, NotExpr target_6, ExprStmt target_10, AddressOfExpr target_11, ValueFieldAccess target_8) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="p"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_492
		and target_2.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vperror_object_484
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_10.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_11.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vi_ctx_p_492, AddressOfExpr target_11, ValueFieldAccess target_8) {
	exists(ValueFieldAccess target_3 |
		target_3.getTarget().getName()="p"
		and target_3.getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_3.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_3.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_492
		and target_11.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_4(Variable vi_ctx_p_492, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="p"
		and target_4.getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_4.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_4.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_492
}

predicate func_5(Function func, PrefixIncrExpr target_5) {
		target_5.getOperand() instanceof ValueFieldAccess
		and target_5.getEnclosingFunction() = func
}

predicate func_6(NotExpr target_6) {
		target_6.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_7(Parameter vpexit_code_484, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpexit_code_484
		and target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="intval"
		and target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="p"
		and target_7.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
}

predicate func_8(Variable vi_ctx_p_492, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="stack"
		and target_8.getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_8.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_492
}

predicate func_9(Variable vi_ctx_p_492, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("errorexec_find")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_492
		and target_9.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="p"
		and target_9.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_9.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_9.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_492
}

predicate func_10(Parameter vperror_object_484, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("ref")
		and target_10.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vperror_object_484
}

predicate func_11(Variable vi_ctx_p_492, AddressOfExpr target_11) {
		target_11.getOperand().(ValueFieldAccess).getTarget().getName()="system_dict"
		and target_11.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dict_stack"
		and target_11.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_492
}

from Function func, Parameter vpexit_code_484, Parameter vperror_object_484, Variable vi_ctx_p_492, ValueFieldAccess target_4, PrefixIncrExpr target_5, NotExpr target_6, ExprStmt target_7, ValueFieldAccess target_8, ExprStmt target_9, ExprStmt target_10, AddressOfExpr target_11
where
not func_0(func)
and not func_1(vpexit_code_484, vi_ctx_p_492, target_6, target_7, target_8, target_9)
and not func_2(vperror_object_484, vi_ctx_p_492, target_6, target_10, target_11, target_8)
and func_4(vi_ctx_p_492, target_4)
and func_5(func, target_5)
and func_6(target_6)
and func_7(vpexit_code_484, target_7)
and func_8(vi_ctx_p_492, target_8)
and func_9(vi_ctx_p_492, target_9)
and func_10(vperror_object_484, target_10)
and func_11(vi_ctx_p_492, target_11)
and vpexit_code_484.getType().hasName("int *")
and vperror_object_484.getType().hasName("ref *")
and vi_ctx_p_492.getType().hasName("i_ctx_t *")
and vpexit_code_484.getFunction() = func
and vperror_object_484.getFunction() = func
and vi_ctx_p_492.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
