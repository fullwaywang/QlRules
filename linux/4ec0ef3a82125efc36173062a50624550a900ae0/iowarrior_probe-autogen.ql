/**
 * @name linux-4ec0ef3a82125efc36173062a50624550a900ae0-iowarrior_probe
 * @id cpp/linux/4ec0ef3a82125efc36173062a50624550a900ae0/iowarrior_probe
 * @description linux-4ec0ef3a82125efc36173062a50624550a900ae0-iowarrior_probe 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinterface_757, Variable viface_desc_762, Variable vretval_765, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="bNumEndpoints"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viface_desc_762
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dev_err")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinterface_757
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Invalid number of endpoints\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_765
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_0))
}

predicate func_4(Parameter vinterface_757) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="cur_altsetting"
		and target_4.getQualifier().(VariableAccess).getTarget()=vinterface_757)
}

predicate func_5(Parameter vinterface_757, Variable viface_desc_762) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=viface_desc_762
		and target_5.getRValue().(PointerFieldAccess).getTarget().getName()="cur_altsetting"
		and target_5.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinterface_757)
}

from Function func, Parameter vinterface_757, Variable viface_desc_762, Variable vretval_765
where
not func_0(vinterface_757, viface_desc_762, vretval_765, func)
and vinterface_757.getType().hasName("usb_interface *")
and func_4(vinterface_757)
and viface_desc_762.getType().hasName("usb_host_interface *")
and func_5(vinterface_757, viface_desc_762)
and vretval_765.getType().hasName("int")
and vinterface_757.getParentScope+() = func
and viface_desc_762.getParentScope+() = func
and vretval_765.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
