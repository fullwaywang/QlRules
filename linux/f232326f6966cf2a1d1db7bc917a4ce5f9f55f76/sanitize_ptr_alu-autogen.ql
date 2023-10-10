/**
 * @name linux-f232326f6966cf2a1d1db7bc917a4ce5f9f55f76-sanitize_ptr_alu
 * @id cpp/linux/f232326f6966cf2a1d1db7bc917a4ce5f9f55f76/sanitize-ptr-alu
 * @description linux-f232326f6966cf2a1d1db7bc917a4ce5f9f55f76-sanitize_ptr_alu 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="13"
		and not target_0.getValue()="0"
		and target_0.getParent().(UnaryMinusExpr).getParent().(ReturnStmt).getExpr() instanceof UnaryMinusExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		func.getEntryPoint().(BlockStmt).getStmt(7)=target_1)
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_2))
}

predicate func_3(Function func) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_3.getGreaterOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getType().hasName("int")
		and target_3.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_5))
}

predicate func_8(Parameter vptr_reg_5926, Parameter voff_is_neg_5928, Variable vopcode_5933, Variable valu_limit_5934) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("retrieve_ptr_limit")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vptr_reg_5926
		and target_8.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=valu_limit_5934
		and target_8.getArgument(2).(VariableAccess).getTarget()=vopcode_5933
		and target_8.getArgument(3).(VariableAccess).getTarget()=voff_is_neg_5928)
}

predicate func_9(Variable vaux_5931, Variable valu_state_5934, Variable valu_limit_5934) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("update_alu_sanitation_state")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vaux_5931
		and target_9.getArgument(1).(VariableAccess).getTarget()=valu_state_5934
		and target_9.getArgument(2).(VariableAccess).getTarget()=valu_limit_5934)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="0"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(UnaryMinusExpr target_11 |
		target_11.getValue()="-13"
		and target_11.getOperand() instanceof Literal
		and target_11.getEnclosingFunction() = func)
}

from Function func, Parameter vptr_reg_5926, Parameter voff_is_neg_5928, Variable vaux_5931, Variable vopcode_5933, Variable valu_state_5934, Variable valu_limit_5934
where
func_0(func)
and not func_1(func)
and not func_2(func)
and not func_3(func)
and not func_5(func)
and func_8(vptr_reg_5926, voff_is_neg_5928, vopcode_5933, valu_limit_5934)
and func_9(vaux_5931, valu_state_5934, valu_limit_5934)
and func_10(func)
and func_11(func)
and vptr_reg_5926.getType().hasName("const bpf_reg_state *")
and voff_is_neg_5928.getType().hasName("bool")
and vaux_5931.getType().hasName("bpf_insn_aux_data *")
and vopcode_5933.getType().hasName("u8")
and valu_state_5934.getType().hasName("u32")
and valu_limit_5934.getType().hasName("u32")
and vptr_reg_5926.getParentScope+() = func
and voff_is_neg_5928.getParentScope+() = func
and vaux_5931.getParentScope+() = func
and vopcode_5933.getParentScope+() = func
and valu_state_5934.getParentScope+() = func
and valu_limit_5934.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
