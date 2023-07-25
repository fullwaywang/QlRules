/**
 * @name freerdp-2215fef975b963b3995356c3583f0e87cd08ac6b-rdpsnd_treat_wave
 * @id cpp/freerdp/2215fef975b963b3995356c3583f0e87cd08ac6b/rdpsnd-treat-wave
 * @description freerdp-2215fef975b963b3995356c3583f0e87cd08ac6b-channels/rdpsnd/client/rdpsnd_main.c-rdpsnd_treat_wave CVE-2020-11041
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrdpsnd_541, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="wCurrentFormatNo"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdpsnd_541
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="NumberOfClientFormats"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdpsnd_541
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1359"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vrdpsnd_541, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ClientFormats"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdpsnd_541
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="wCurrentFormatNo"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdpsnd_541
}

from Function func, Parameter vrdpsnd_541, ExprStmt target_1
where
not func_0(vrdpsnd_541, target_1, func)
and func_1(vrdpsnd_541, target_1)
and vrdpsnd_541.getType().hasName("rdpsndPlugin *")
and vrdpsnd_541.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
