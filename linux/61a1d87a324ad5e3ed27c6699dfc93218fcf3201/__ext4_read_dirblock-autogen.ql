/**
 * @name linux-61a1d87a324ad5e3ed27c6699dfc93218fcf3201-__ext4_read_dirblock
 * @id cpp/linux/61a1d87a324ad5e3ed27c6699dfc93218fcf3201/__ext4_read_dirblock
 * @description linux-61a1d87a324ad5e3ed27c6699dfc93218fcf3201-__ext4_read_dirblock CVE-2022-1184
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_119, Parameter vblock_120, Parameter vfunc_122, Parameter vline_123) {
	exists(BinaryBitwiseOperation target_0 |
		target_0.getLeftOperand() instanceof PointerFieldAccess
		and target_0.getRightOperand().(PointerFieldAccess).getTarget().getName()="i_blkbits"
		and target_0.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_119
		and target_0.getParent().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vblock_120
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_error_inode")
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_119
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfunc_122
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vline_123
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vblock_120
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Attempting to read directory block (%u) that is past i_size (%llu)"
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vblock_120
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="i_size"
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_119)
}

predicate func_1(Parameter vinode_119) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="i_size"
		and target_1.getQualifier().(VariableAccess).getTarget()=vinode_119)
}

from Function func, Parameter vinode_119, Parameter vblock_120, Parameter vfunc_122, Parameter vline_123
where
not func_0(vinode_119, vblock_120, vfunc_122, vline_123)
and func_1(vinode_119)
and vinode_119.getType().hasName("inode *")
and vblock_120.getType().hasName("ext4_lblk_t")
and vfunc_122.getType().hasName("const char *")
and vline_123.getType().hasName("unsigned int")
and vinode_119.getParentScope+() = func
and vblock_120.getParentScope+() = func
and vfunc_122.getParentScope+() = func
and vline_123.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
