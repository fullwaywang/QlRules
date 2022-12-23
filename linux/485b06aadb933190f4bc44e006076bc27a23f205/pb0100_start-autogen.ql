/**
 * @name linux-485b06aadb933190f4bc44e006076bc27a23f205-pb0100_start
 * @id cpp/linux/485b06aadb933190f4bc44e006076bc27a23f205/pb0100-start
 * @description linux-485b06aadb933190f4bc44e006076bc27a23f205-pb0100_start 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable valt_178, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="bNumEndpoints"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valt_178
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Variable valt_178) {
	exists(NotExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=valt_178
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19")
}

from Function func, Variable valt_178
where
not func_0(valt_178, func)
and valt_178.getType().hasName("usb_host_interface *")
and func_1(valt_178)
and valt_178.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
