/**
 * @name linux-76d56d4ab4f2a9e4f085c7d77172194ddaccf7d2-do_read_inode
 * @id cpp/linux/76d56d4ab4f2a9e4f085c7d77172194ddaccf7d2/do_read_inode
 * @description linux-76d56d4ab4f2a9e4f085c7d77172194ddaccf7d2-do_read_inode 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_211, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sanity_check_inode")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_211
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_0))
}

predicate func_2(Variable vnode_page_215, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("f2fs_put_page")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnode_page_215
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(46)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(46).getFollowingStmt()=target_2))
}

predicate func_4(Variable vnode_page_215, Parameter vinode_211) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("__recover_inline_status")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vinode_211
		and target_4.getArgument(1).(VariableAccess).getTarget()=vnode_page_215)
}

predicate func_5(Variable vri_216, Parameter vinode_211) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("get_inline_info")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vinode_211
		and target_5.getArgument(1).(VariableAccess).getTarget()=vri_216)
}

from Function func, Variable vnode_page_215, Variable vri_216, Parameter vinode_211
where
not func_0(vinode_211, func)
and not func_2(vnode_page_215, func)
and vnode_page_215.getType().hasName("page *")
and func_4(vnode_page_215, vinode_211)
and vinode_211.getType().hasName("inode *")
and func_5(vri_216, vinode_211)
and vnode_page_215.getParentScope+() = func
and vri_216.getParentScope+() = func
and vinode_211.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
