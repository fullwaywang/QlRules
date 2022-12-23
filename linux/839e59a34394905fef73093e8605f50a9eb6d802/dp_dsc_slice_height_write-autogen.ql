/**
 * @name linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_dsc_slice_height_write
 * @id cpp/linux/839e59a34394905fef73093e8605f50a9eb6d802/dp-dsc-slice-height-write
 * @description linux-839e59a34394905fef73093e8605f50a9eb6d802-dp_dsc_slice_height_write CVE-2021-42327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vwr_buf_1757, Variable vmax_param_num_1759, Variable vparam_nums_1760, Variable vparam_1761, Parameter vsize_1748, Parameter vbuf_1747) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vsize_1748
		and target_1.getParent().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_1757
		and target_1.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vparam_1761
		and target_1.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_1747
		and target_1.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmax_param_num_1759
		and target_1.getParent().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparam_nums_1760
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwr_buf_1757
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

from Function func, Variable vwr_buf_1757, Variable vmax_param_num_1759, Variable vparam_nums_1760, Variable vparam_1761, Parameter vsize_1748, Parameter vbuf_1747
where
func_1(vwr_buf_1757, vmax_param_num_1759, vparam_nums_1760, vparam_1761, vsize_1748, vbuf_1747)
and vwr_buf_1757.getType().hasName("char *")
and vmax_param_num_1759.getType().hasName("int")
and vparam_nums_1760.getType().hasName("uint8_t")
and vparam_1761.getType().hasName("long[1]")
and vsize_1748.getType().hasName("size_t")
and vbuf_1747.getType().hasName("const char *")
and vwr_buf_1757.getParentScope+() = func
and vmax_param_num_1759.getParentScope+() = func
and vparam_nums_1760.getParentScope+() = func
and vparam_1761.getParentScope+() = func
and vsize_1748.getParentScope+() = func
and vbuf_1747.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
