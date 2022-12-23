/**
 * @name linux-049c4e13714ecbca567b4d5f6d563f05d431c80e-scalar32_min_max_xor
 * @id cpp/linux/049c4e13714ecbca567b4d5f6d563f05d431c80e/scalar32_min_max_xor
 * @description linux-049c4e13714ecbca567b4d5f6d563f05d431c80e-scalar32_min_max_xor 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vdst_reg_7219, Variable vsrc_known_7222, Variable vdst_known_7223, Variable vvar32_off_7224) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__mark_reg32_known")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdst_reg_7219
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="value"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vvar32_off_7224
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vsrc_known_7222
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vdst_known_7223)
}

predicate func_1(Variable vsrc_known_7222, Variable vdst_known_7223) {
	exists(ReturnStmt target_1 |
		target_1.toString() = "return ..."
		and target_1.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vsrc_known_7222
		and target_1.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vdst_known_7223)
}

predicate func_2(Parameter vdst_reg_7219) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="var_off"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdst_reg_7219)
}

from Function func, Parameter vdst_reg_7219, Variable vsrc_known_7222, Variable vdst_known_7223, Variable vvar32_off_7224
where
not func_0(vdst_reg_7219, vsrc_known_7222, vdst_known_7223, vvar32_off_7224)
and func_1(vsrc_known_7222, vdst_known_7223)
and vdst_reg_7219.getType().hasName("bpf_reg_state *")
and func_2(vdst_reg_7219)
and vsrc_known_7222.getType().hasName("bool")
and vdst_known_7223.getType().hasName("bool")
and vvar32_off_7224.getType().hasName("tnum")
and vdst_reg_7219.getParentScope+() = func
and vsrc_known_7222.getParentScope+() = func
and vdst_known_7223.getParentScope+() = func
and vvar32_off_7224.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
