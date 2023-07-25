/**
 * @name ghostscript-34cc326eb2c5695833361887fe0b32e8d987741c-copy_stack
 * @id cpp/ghostscript/34cc326eb2c5695833361887fe0b32e8d987741c/copy-stack
 * @description ghostscript-34cc326eb2c5695833361887fe0b32e8d987741c-psi/interp.c-copy_stack CVE-2018-18073
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vi_ctx_p_760, Parameter vpstack_760, Variable vsize_762, AddressOfExpr target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpstack_760
		and target_1.getCondition().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="stack"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="exec_stack"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_760
		and target_1.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_762
		and target_1.getThen().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("errorexec_find")
		and target_1.getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1)
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vi_ctx_p_760, AddressOfExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_760
}

predicate func_3(Parameter vi_ctx_p_760, Parameter vpstack_760, Variable vsize_762, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ref_stack_store")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpstack_760
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("ref *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_762
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_760
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(StringLiteral).getValue()="copy_stack"
}

from Function func, Parameter vi_ctx_p_760, Parameter vpstack_760, Variable vsize_762, AddressOfExpr target_2, ExprStmt target_3
where
not func_1(vi_ctx_p_760, vpstack_760, vsize_762, target_2, target_3, func)
and func_2(vi_ctx_p_760, target_2)
and func_3(vi_ctx_p_760, vpstack_760, vsize_762, target_3)
and vi_ctx_p_760.getType().hasName("i_ctx_t *")
and vpstack_760.getType().hasName("const ref_stack_t *")
and vsize_762.getType().hasName("uint")
and vi_ctx_p_760.getFunction() = func
and vpstack_760.getFunction() = func
and vsize_762.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
