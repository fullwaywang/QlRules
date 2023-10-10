/**
 * @name linux-162f98dea487206d9ab79fc12ed64700667a894d-gtco_probe
 * @id cpp/linux/162f98dea487206d9ab79fc12ed64700667a894d/gtco_probe
 * @description linux-162f98dea487206d9ab79fc12ed64700667a894d-gtco_probe 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vusbinterface_816, Variable verror_825, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="bNumEndpoints"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="desc"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="altsetting"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vusbinterface_816
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dev_err")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vusbinterface_816
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Invalid number of endpoints\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_825
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_0))
}

predicate func_4(Parameter vusbinterface_816) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="dev"
		and target_4.getQualifier().(VariableAccess).getTarget()=vusbinterface_816)
}

from Function func, Parameter vusbinterface_816, Variable verror_825
where
not func_0(vusbinterface_816, verror_825, func)
and vusbinterface_816.getType().hasName("usb_interface *")
and func_4(vusbinterface_816)
and verror_825.getType().hasName("int")
and vusbinterface_816.getParentScope+() = func
and verror_825.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
