/**
 * @name linux-049c4e13714ecbca567b4d5f6d563f05d431c80e-scalar32_min_max_or
 * @id cpp/linux/049c4e13714ecbca567b4d5f6d563f05d431c80e/scalar32_min_max_or
 * @description linux-049c4e13714ecbca567b4d5f6d563f05d431c80e-scalar32_min_max_or 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vdst_reg_7149, Variable vsrc_known_7152, Variable vdst_known_7153, Variable vvar32_off_7154) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__mark_reg32_known")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdst_reg_7149
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="value"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vvar32_off_7154
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vsrc_known_7152
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vdst_known_7153)
}

predicate func_1(Variable vsrc_known_7152, Variable vdst_known_7153) {
	exists(ReturnStmt target_1 |
		target_1.toString() = "return ..."
		and target_1.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vsrc_known_7152
		and target_1.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vdst_known_7153)
}

predicate func_2(Parameter vdst_reg_7149) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="var_off"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdst_reg_7149)
}

from Function func, Parameter vdst_reg_7149, Variable vsrc_known_7152, Variable vdst_known_7153, Variable vvar32_off_7154
where
not func_0(vdst_reg_7149, vsrc_known_7152, vdst_known_7153, vvar32_off_7154)
and func_1(vsrc_known_7152, vdst_known_7153)
and vdst_reg_7149.getType().hasName("bpf_reg_state *")
and func_2(vdst_reg_7149)
and vsrc_known_7152.getType().hasName("bool")
and vdst_known_7153.getType().hasName("bool")
and vvar32_off_7154.getType().hasName("tnum")
and vdst_reg_7149.getParentScope+() = func
and vsrc_known_7152.getParentScope+() = func
and vdst_known_7153.getParentScope+() = func
and vvar32_off_7154.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
