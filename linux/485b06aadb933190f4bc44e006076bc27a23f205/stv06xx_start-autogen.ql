/**
 * @name linux-485b06aadb933190f4bc44e006076bc27a23f205-stv06xx_start
 * @id cpp/linux/485b06aadb933190f4bc44e006076bc27a23f205/stv06xx-start
 * @description linux-485b06aadb933190f4bc44e006076bc27a23f205-stv06xx_start NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable valt_274, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="bNumEndpoints"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valt_274
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Variable valt_274, Parameter vgspca_dev_271) {
	exists(NotExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=valt_274
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3%s: Couldn't get altsetting\n"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="v4l2_dev"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgspca_dev_271
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5")
}

from Function func, Variable valt_274, Parameter vgspca_dev_271
where
not func_0(valt_274, func)
and valt_274.getType().hasName("usb_host_interface *")
and func_1(valt_274, vgspca_dev_271)
and vgspca_dev_271.getType().hasName("gspca_dev *")
and valt_274.getParentScope+() = func
and vgspca_dev_271.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
