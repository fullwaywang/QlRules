/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_nvm_fixup_sband_iftd
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-nvm-fixup-sband-iftd
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_nvm_fixup_sband_iftd CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrans_727, Parameter viftype_data_729, Variable vis_ap_733, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_727
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vis_ap_733
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vendor_elems"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viftype_data_729
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("const u8[8]")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vendor_elems"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viftype_data_729
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getType().hasName("const u8[8]")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const u8[8]")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_3(Parameter vtrans_727) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="hw_rf_id"
		and target_3.getQualifier().(VariableAccess).getTarget()=vtrans_727)
}

predicate func_4(Parameter viftype_data_729) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="he_cap"
		and target_4.getQualifier().(VariableAccess).getTarget()=viftype_data_729)
}

predicate func_5(Parameter viftype_data_729, Variable vis_ap_733) {
	exists(NotExpr target_5 |
		target_5.getOperand().(VariableAccess).getTarget()=vis_ap_733
		and target_5.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="phy_cap_info"
		and target_5.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="he_cap_elem"
		and target_5.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="he_cap"
		and target_5.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viftype_data_729
		and target_5.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="9"
		and target_5.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="8")
}

from Function func, Parameter vtrans_727, Parameter viftype_data_729, Variable vis_ap_733
where
not func_0(vtrans_727, viftype_data_729, vis_ap_733, func)
and vtrans_727.getType().hasName("iwl_trans *")
and func_3(vtrans_727)
and viftype_data_729.getType().hasName("ieee80211_sband_iftype_data *")
and func_4(viftype_data_729)
and vis_ap_733.getType().hasName("bool")
and func_5(viftype_data_729, vis_ap_733)
and vtrans_727.getParentScope+() = func
and viftype_data_729.getParentScope+() = func
and vis_ap_733.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
