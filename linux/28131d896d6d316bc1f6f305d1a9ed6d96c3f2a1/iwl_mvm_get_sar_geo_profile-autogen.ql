/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_get_sar_geo_profile
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-get-sar-geo-profile
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_get_sar_geo_profile CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vret_763) {
	exists(Literal target_2 |
		target_2.getValue()="3"
		and not target_2.getValue()="8"
		and target_2.getParent().(GTExpr).getParent().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vret_763)
}

predicate func_6(Variable vgeo_tx_cmd_760, Variable vlen_762, Variable vcmd_ver_765) {
	exists(IfStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcmd_ver_765
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_762
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getValue()="72"
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="v4"
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vgeo_tx_cmd_760
		and target_6.getElse() instanceof IfStmt
		and target_6.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcmd_ver_765
		and target_6.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="5")
}

predicate func_7(Variable vret_763, Parameter vmvm_758, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition().(VariableAccess).getTarget()=vret_763
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(FunctionDeclarationEntry).getType() instanceof VoidType
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(StringLiteral).getValue()="Failed to get geographic profile info %d\n"
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Failed to get geographic profile info %d\n"
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__compiletime_assert_2112")
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__iwl_err")
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_758
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Failed to get geographic profile info %d\n"
		and target_7.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vret_763
		and target_7.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_763
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_7))
}

predicate func_8(Variable vgeo_tx_cmd_760, Variable vlen_762, Variable vcmd_ver_765, Parameter vmvm_758, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcmd_ver_765
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_762
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getValue()="44"
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="v3"
		and target_8.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vgeo_tx_cmd_760
		and target_8.getElse().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("fw_has_api")
		and target_8.getElse().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ucode_capa"
		and target_8.getElse().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="fw"
		and target_8.getElse().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fwrt"
		and target_8.getElse().(IfStmt).getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_758
		and target_8.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_762
		and target_8.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="v2"
		and target_8.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vgeo_tx_cmd_760
		and target_8.getElse().(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_762
		and target_8.getElse().(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="v1"
		and target_8.getElse().(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vgeo_tx_cmd_760
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_11(Variable vgeo_tx_cmd_760, Variable vlen_762, Variable vcmd_ver_765) {
	exists(EqualityOperation target_11 |
		target_11.getAnOperand().(VariableAccess).getTarget()=vcmd_ver_765
		and target_11.getAnOperand().(Literal).getValue()="3"
		and target_11.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_762
		and target_11.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="v3"
		and target_11.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vgeo_tx_cmd_760)
}

from Function func, Variable vgeo_tx_cmd_760, Variable vlen_762, Variable vret_763, Variable vcmd_ver_765, Parameter vmvm_758
where
func_2(vret_763)
and not func_6(vgeo_tx_cmd_760, vlen_762, vcmd_ver_765)
and not func_7(vret_763, vmvm_758, func)
and func_8(vgeo_tx_cmd_760, vlen_762, vcmd_ver_765, vmvm_758, func)
and vgeo_tx_cmd_760.getType().hasName("iwl_geo_tx_power_profiles_cmd")
and vlen_762.getType().hasName("u16")
and vret_763.getType().hasName("int")
and vcmd_ver_765.getType().hasName("u8")
and func_11(vgeo_tx_cmd_760, vlen_762, vcmd_ver_765)
and vmvm_758.getType().hasName("iwl_mvm *")
and vgeo_tx_cmd_760.getParentScope+() = func
and vlen_762.getParentScope+() = func
and vret_763.getParentScope+() = func
and vcmd_ver_765.getParentScope+() = func
and vmvm_758.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
