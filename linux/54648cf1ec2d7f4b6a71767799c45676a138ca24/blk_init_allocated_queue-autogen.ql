/**
 * @name linux-54648cf1ec2d7f4b6a71767799c45676a138ca24-blk_init_allocated_queue
 * @id cpp/linux/54648cf1ec2d7f4b6a71767799c45676a138ca24/blk_init_allocated_queue
 * @description linux-54648cf1ec2d7f4b6a71767799c45676a138ca24-blk_init_allocated_queue 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vq_1154, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fq"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_1154
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vq_1154) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="fq"
		and target_1.getQualifier().(VariableAccess).getTarget()=vq_1154)
}

from Function func, Parameter vq_1154
where
not func_0(vq_1154, func)
and vq_1154.getType().hasName("request_queue *")
and func_1(vq_1154)
and vq_1154.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
