/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_mac_ctxt_send_beacon_v9
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-mac-ctxt-send-beacon-v9
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_mac_ctxt_send_beacon_v9 CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrate_928) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("iwl_mvm_mac80211_idx_to_hwrate")
		and not target_0.getTarget().hasName("iwl_fw_lookup_cmd_ver")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vrate_928)
}

predicate func_4(Variable vrate_928, Parameter vmvm_921) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("iwl_mvm_mac_ctxt_get_beacon_flags")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="fw"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_921
		and target_4.getArgument(1).(VariableAccess).getTarget()=vrate_928)
}

predicate func_5(Parameter vmvm_921) {
	exists(ConditionalExpr target_5 |
		target_5.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("iwl_fw_lookup_cmd_ver")
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fw"
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_921
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="10")
}

predicate func_8(Variable vbeacon_cmd_927, Variable vctx_930, Parameter vvif_922) {
	exists(LogicalAndExpr target_8 |
		target_8.getAnOperand().(FunctionCall).getTarget().hasName("cfg80211_channel_is_psc")
		and target_8.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="chan"
		and target_8.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="def"
		and target_8.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_930
		and target_8.getAnOperand().(NotExpr).getValue()="1"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof AssignOrExpr
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="short_ssid"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbeacon_cmd_927
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getTarget().hasName("crc32_le")
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(0).(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="ssid"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bss_conf"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvif_922
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="ssid_len"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bss_conf"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvif_922)
}

predicate func_12(Variable vbeacon_cmd_927, Variable vflags_929, Parameter vvif_922, Function func) {
	exists(IfStmt target_12 |
		target_12.getCondition() instanceof LogicalAndExpr
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vflags_929
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue() instanceof EnumConstantAccess
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="short_ssid"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbeacon_cmd_927
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getTarget().hasName("crc32_le")
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(0).(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="ssid"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bss_conf"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvif_922
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="ssid_len"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bss_conf"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvif_922
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12)
}

from Function func, Variable vbeacon_cmd_927, Variable vrate_928, Variable vflags_929, Variable vctx_930, Parameter vmvm_921, Parameter vvif_922
where
func_0(vrate_928)
and not func_4(vrate_928, vmvm_921)
and not func_5(vmvm_921)
and func_8(vbeacon_cmd_927, vctx_930, vvif_922)
and func_12(vbeacon_cmd_927, vflags_929, vvif_922, func)
and vbeacon_cmd_927.getType().hasName("iwl_mac_beacon_cmd")
and vrate_928.getType().hasName("u8")
and vflags_929.getType().hasName("u16")
and vctx_930.getType().hasName("ieee80211_chanctx_conf *")
and vmvm_921.getType().hasName("iwl_mvm *")
and vvif_922.getType().hasName("ieee80211_vif *")
and vbeacon_cmd_927.getParentScope+() = func
and vrate_928.getParentScope+() = func
and vflags_929.getParentScope+() = func
and vctx_930.getParentScope+() = func
and vmvm_921.getParentScope+() = func
and vvif_922.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
