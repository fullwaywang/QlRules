/**
 * @name linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_phy_test_pattern_debugfs_write
 * @id cpp/linux/839e59a34394905fef73093e8605f50a9eb6d802/dp-phy-test-pattern-debugfs-write
 * @description linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_phy_test_pattern_debugfs_write CVE-2021-42327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vparam_621, Variable vmax_param_num_622, Variable vparam_nums_626, Parameter vsize_615, Variable vwr_buf_619, Parameter vbuf_614) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vsize_615
		and target_1.getParent().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_619
		and target_1.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vparam_621
		and target_1.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_614
		and target_1.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmax_param_num_622
		and target_1.getParent().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparam_nums_626
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_619
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

from Function func, Variable vparam_621, Variable vmax_param_num_622, Variable vparam_nums_626, Parameter vsize_615, Variable vwr_buf_619, Parameter vbuf_614
where
func_1(vparam_621, vmax_param_num_622, vparam_nums_626, vsize_615, vwr_buf_619, vbuf_614)
and vparam_621.getType().hasName("long[11]")
and vmax_param_num_622.getType().hasName("int")
and vparam_nums_626.getType().hasName("uint8_t")
and vsize_615.getType().hasName("size_t")
and vwr_buf_619.getType().hasName("char *")
and vbuf_614.getType().hasName("const char *")
and vparam_621.getParentScope+() = func
and vmax_param_num_622.getParentScope+() = func
and vparam_nums_626.getParentScope+() = func
and vsize_615.getParentScope+() = func
and vwr_buf_619.getParentScope+() = func
and vbuf_614.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
