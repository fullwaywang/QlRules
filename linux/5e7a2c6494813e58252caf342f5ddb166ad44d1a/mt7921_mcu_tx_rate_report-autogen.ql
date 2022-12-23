/**
 * @name linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7921_mcu_tx_rate_report
 * @id cpp/linux/5e7a2c6494813e58252caf342f5ddb166ad44d1a/mt7921-mcu-tx-rate-report
 * @description linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7921_mcu_tx_rate_report CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwtbl_info_405, Variable vcurr_idx_408) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vcurr_idx_408
		and target_0.getParent().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="rate"
		and target_0.getParent().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rate_info"
		and target_0.getParent().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwtbl_info_405)
}

predicate func_1(Function func) {
	exists(VariableDeclarationEntry target_1 |
		target_1.getVariable().getInitializer().(Initializer).getExpr() instanceof ValueFieldAccess
		and target_1.getDeclaration().getParentScope+() = func)
}

predicate func_2(Variable vwtbl_info_405) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vwtbl_info_405
		and target_2.getRValue() instanceof PointerFieldAccess)
}

predicate func_3(Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("u8")
		and target_3.getExpr().(AssignExpr).getRValue() instanceof ValueFieldAccess
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_3))
}

predicate func_4(Variable vwtbl_info_405, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("u8")
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="8"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(DivExpr).getValue()="8"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="rate"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rate_info"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwtbl_info_405
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="rate"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rate_info"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwtbl_info_405
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="0"
		and target_4.getThen().(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_4))
}

predicate func_5(Variable vwtbl_info_405, Variable vrate_407, Variable vmphy_411, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("mt7921_mcu_tx_rate_parse")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmphy_411
		and target_5.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="peer_cap"
		and target_5.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwtbl_info_405
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrate_407
		and target_5.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="rate"
		and target_5.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rate_info"
		and target_5.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwtbl_info_405
		and target_5.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("u8")
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_5))
}

predicate func_8(Parameter vskb_402) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="data"
		and target_8.getQualifier().(VariableAccess).getTarget()=vskb_402)
}

predicate func_9(Variable vwtbl_info_405) {
	exists(ValueFieldAccess target_9 |
		target_9.getTarget().getName()="rate_idx"
		and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="rate_info"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwtbl_info_405)
}

predicate func_11(Function func) {
	exists(Initializer target_11 |
		target_11.getExpr() instanceof PointerFieldAccess
		and target_11.getExpr().getEnclosingFunction() = func)
}

predicate func_12(Variable vwtbl_info_405, Variable vcurr_idx_408, Function func) {
	exists(DeclStmt target_12 |
		target_12.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="rate"
		and target_12.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rate_info"
		and target_12.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwtbl_info_405
		and target_12.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcurr_idx_408
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12)
}

predicate func_13(Variable vwtbl_info_405, Function func) {
	exists(DeclStmt target_13 |
		target_13.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="peer_cap"
		and target_13.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwtbl_info_405
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13)
}

predicate func_15(Variable vrate_407, Variable vcurr_409, Variable vpeer_410, Variable vmphy_411) {
	exists(VariableAccess target_15 |
		target_15.getTarget()=vcurr_409
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mt7921_mcu_tx_rate_parse")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmphy_411
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpeer_410
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrate_407)
}

predicate func_16(Variable vwtbl_info_405) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="rate_info"
		and target_16.getQualifier().(VariableAccess).getTarget()=vwtbl_info_405)
}

from Function func, Parameter vskb_402, Variable vwtbl_info_405, Variable vrate_407, Variable vcurr_idx_408, Variable vcurr_409, Variable vpeer_410, Variable vmphy_411
where
func_0(vwtbl_info_405, vcurr_idx_408)
and func_1(func)
and not func_2(vwtbl_info_405)
and not func_3(func)
and not func_4(vwtbl_info_405, func)
and not func_5(vwtbl_info_405, vrate_407, vmphy_411, func)
and func_8(vskb_402)
and func_9(vwtbl_info_405)
and func_11(func)
and func_12(vwtbl_info_405, vcurr_idx_408, func)
and func_13(vwtbl_info_405, func)
and func_15(vrate_407, vcurr_409, vpeer_410, vmphy_411)
and vskb_402.getType().hasName("sk_buff *")
and vwtbl_info_405.getType().hasName("mt7921_mcu_wlan_info_event *")
and func_16(vwtbl_info_405)
and vrate_407.getType().hasName("rate_info")
and vcurr_409.getType().hasName("u16")
and vpeer_410.getType().hasName("mt7921_mcu_peer_cap")
and vmphy_411.getType().hasName("mt76_phy *")
and vskb_402.getParentScope+() = func
and vwtbl_info_405.getParentScope+() = func
and vrate_407.getParentScope+() = func
and vcurr_idx_408.getParentScope+() = func
and vcurr_409.getParentScope+() = func
and vpeer_410.getParentScope+() = func
and vmphy_411.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
