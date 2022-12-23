/**
 * @name linux-049c4e13714ecbca567b4d5f6d563f05d431c80e-scalar32_min_max_and
 * @id cpp/linux/049c4e13714ecbca567b4d5f6d563f05d431c80e/scalar32_min_max_and
 * @description linux-049c4e13714ecbca567b4d5f6d563f05d431c80e-scalar32_min_max_and 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vdst_reg_7078, Variable vsrc_known_7081, Variable vdst_known_7082, Variable vvar32_off_7083) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__mark_reg32_known")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdst_reg_7078
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="value"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vvar32_off_7083
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vsrc_known_7081
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vdst_known_7082)
}

predicate func_1(Variable vsrc_known_7081, Variable vdst_known_7082) {
	exists(ReturnStmt target_1 |
		target_1.toString() = "return ..."
		and target_1.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vsrc_known_7081
		and target_1.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vdst_known_7082)
}

predicate func_2(Parameter vdst_reg_7078) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="var_off"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdst_reg_7078)
}

from Function func, Parameter vdst_reg_7078, Variable vsrc_known_7081, Variable vdst_known_7082, Variable vvar32_off_7083
where
not func_0(vdst_reg_7078, vsrc_known_7081, vdst_known_7082, vvar32_off_7083)
and func_1(vsrc_known_7081, vdst_known_7082)
and vdst_reg_7078.getType().hasName("bpf_reg_state *")
and func_2(vdst_reg_7078)
and vsrc_known_7081.getType().hasName("bool")
and vdst_known_7082.getType().hasName("bool")
and vvar32_off_7083.getType().hasName("tnum")
and vdst_reg_7078.getParentScope+() = func
and vsrc_known_7081.getParentScope+() = func
and vdst_known_7082.getParentScope+() = func
and vvar32_off_7083.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
