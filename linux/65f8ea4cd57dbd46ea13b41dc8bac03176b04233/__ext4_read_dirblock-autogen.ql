/**
 * @name linux-65f8ea4cd57dbd46ea13b41dc8bac03176b04233-__ext4_read_dirblock
 * @id cpp/linux/65f8ea4cd57dbd46ea13b41dc8bac03176b04233/__ext4_read_dirblock
 * @description linux-65f8ea4cd57dbd46ea13b41dc8bac03176b04233-__ext4_read_dirblock CVE-2022-1184
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_103, Parameter vblock_104, Parameter vfunc_106, Parameter vline_107, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vblock_104
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="i_size"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_103
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_error_inode")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_103
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfunc_106
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vline_107
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vblock_104
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Attempting to read directory block (%u) that is past i_size (%llu)"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vblock_104
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="i_size"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_103
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_PTR")
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getOperand().(Literal).getValue()="117"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

from Function func, Parameter vinode_103, Parameter vblock_104, Parameter vfunc_106, Parameter vline_107
where
not func_0(vinode_103, vblock_104, vfunc_106, vline_107, func)
and vinode_103.getType().hasName("inode *")
and vblock_104.getType().hasName("ext4_lblk_t")
and vfunc_106.getType().hasName("const char *")
and vline_107.getType().hasName("unsigned int")
and vinode_103.getParentScope+() = func
and vblock_104.getParentScope+() = func
and vfunc_106.getParentScope+() = func
and vline_107.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
