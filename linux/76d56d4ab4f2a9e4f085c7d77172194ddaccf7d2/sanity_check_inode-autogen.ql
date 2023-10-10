/**
 * @name linux-76d56d4ab4f2a9e4f085c7d77172194ddaccf7d2-sanity_check_inode
 * @id cpp/linux/76d56d4ab4f2a9e4f085c7d77172194ddaccf7d2/sanity_check_inode
 * @description linux-76d56d4ab4f2a9e4f085c7d77172194ddaccf7d2-sanity_check_inode 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vsbi_198, Variable v__func__, Parameter vinode_196, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("f2fs_has_extra_attr")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_196
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("f2fs_sb_has_extra_attr")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sb"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbi_198
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("set_sbi_flag")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbi_198
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("f2fs_msg")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sb"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbi_198
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s: inode (ino=%lx) is with extra_attr, but extra_attr feature is off"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="i_ino"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_196
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_4(Variable vsbi_198) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="sb"
		and target_4.getQualifier().(VariableAccess).getTarget()=vsbi_198)
}

predicate func_5(Parameter vinode_196) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="i_ino"
		and target_5.getQualifier().(VariableAccess).getTarget()=vinode_196)
}

from Function func, Variable vsbi_198, Variable v__func__, Parameter vinode_196
where
not func_0(vsbi_198, v__func__, vinode_196, func)
and vsbi_198.getType().hasName("f2fs_sb_info *")
and func_4(vsbi_198)
and v__func__.getType().hasName("const char[19]")
and vinode_196.getType().hasName("inode *")
and func_5(vinode_196)
and vsbi_198.getParentScope+() = func
and not v__func__.getParentScope+() = func
and vinode_196.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
