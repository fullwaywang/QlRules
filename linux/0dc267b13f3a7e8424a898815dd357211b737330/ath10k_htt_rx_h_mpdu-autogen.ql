/**
 * @name linux-0dc267b13f3a7e8424a898815dd357211b737330-ath10k_htt_rx_h_mpdu
 * @id cpp/linux/0dc267b13f3a7e8424a898815dd357211b737330/ath10k_htt_rx_h_mpdu
 * @description linux-0dc267b13f3a7e8424a898815dd357211b737330-ath10k_htt_rx_h_mpdu CVE-2020-26141
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vstatus_1830, Parameter vfill_crypt_header_1831, Parameter vfrag_1835, Variable venctype_1842) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vfrag_1835
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vfill_crypt_header_1831
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=venctype_1842
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flag"
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatus_1830
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="4294967287")
}

predicate func_1(Parameter vstatus_1830, Parameter vfill_crypt_header_1831, Parameter vfrag_1835, Variable venctype_1842) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vfrag_1835
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vfill_crypt_header_1831
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=venctype_1842
		and target_1.getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flag"
		and target_1.getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstatus_1830
		and target_1.getThen().(ExprStmt).getExpr().(AssignAndExpr).getRValue().(BitwiseAndExpr).getValue()="4294967271")
}

predicate func_2(Parameter vstatus_1830) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="flag"
		and target_2.getQualifier().(VariableAccess).getTarget()=vstatus_1830)
}

predicate func_3(Parameter var_1828, Parameter vstatus_1830, Variable vmsdu_1839, Variable venctype_1842, Variable vfirst_hdr_1843, Variable vis_decrypted_1849) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("ath10k_htt_rx_h_undecap")
		and target_3.getArgument(0).(VariableAccess).getTarget()=var_1828
		and target_3.getArgument(1).(VariableAccess).getTarget()=vmsdu_1839
		and target_3.getArgument(2).(VariableAccess).getTarget()=vstatus_1830
		and target_3.getArgument(3).(VariableAccess).getTarget()=vfirst_hdr_1843
		and target_3.getArgument(4).(VariableAccess).getTarget()=venctype_1842
		and target_3.getArgument(5).(VariableAccess).getTarget()=vis_decrypted_1849)
}

predicate func_4(Parameter vfill_crypt_header_1831) {
	exists(NotExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=vfill_crypt_header_1831)
}

predicate func_5(Parameter vfill_crypt_header_1831) {
	exists(IfStmt target_5 |
		target_5.getCondition().(VariableAccess).getTarget()=vfill_crypt_header_1831
		and target_5.getThen().(ContinueStmt).toString() = "continue;")
}

predicate func_6(Parameter var_1828, Parameter vfrag_1835, Variable vmsdu_1839, Variable vmulticast_check_1852) {
	exists(IfStmt target_6 |
		target_6.getCondition().(VariableAccess).getTarget()=vfrag_1835
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmulticast_check_1852
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ath10k_htt_rx_h_frag_multicast_check")
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=var_1828
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmsdu_1839
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0")
}

predicate func_7(Parameter var_1828, Parameter vpeer_id_1834, Variable vmsdu_1839, Variable venctype_1842) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("ath10k_htt_rx_h_frag_pn_check")
		and target_7.getArgument(0).(VariableAccess).getTarget()=var_1828
		and target_7.getArgument(1).(VariableAccess).getTarget()=vmsdu_1839
		and target_7.getArgument(2).(VariableAccess).getTarget()=vpeer_id_1834
		and target_7.getArgument(3).(Literal).getValue()="0"
		and target_7.getArgument(4).(VariableAccess).getTarget()=venctype_1842)
}

from Function func, Parameter var_1828, Parameter vstatus_1830, Parameter vfill_crypt_header_1831, Parameter vpeer_id_1834, Parameter vfrag_1835, Variable vmsdu_1839, Variable venctype_1842, Variable vfirst_hdr_1843, Variable vis_decrypted_1849, Variable vmulticast_check_1852
where
not func_0(vstatus_1830, vfill_crypt_header_1831, vfrag_1835, venctype_1842)
and not func_1(vstatus_1830, vfill_crypt_header_1831, vfrag_1835, venctype_1842)
and vstatus_1830.getType().hasName("ieee80211_rx_status *")
and func_2(vstatus_1830)
and func_3(var_1828, vstatus_1830, vmsdu_1839, venctype_1842, vfirst_hdr_1843, vis_decrypted_1849)
and vfill_crypt_header_1831.getType().hasName("bool")
and func_4(vfill_crypt_header_1831)
and func_5(vfill_crypt_header_1831)
and vfrag_1835.getType().hasName("bool")
and func_6(var_1828, vfrag_1835, vmsdu_1839, vmulticast_check_1852)
and vmsdu_1839.getType().hasName("sk_buff *")
and venctype_1842.getType().hasName("htt_rx_mpdu_encrypt_type")
and func_7(var_1828, vpeer_id_1834, vmsdu_1839, venctype_1842)
and vfirst_hdr_1843.getType().hasName("u8[64]")
and vis_decrypted_1849.getType().hasName("bool")
and vmulticast_check_1852.getType().hasName("bool")
and var_1828.getParentScope+() = func
and vstatus_1830.getParentScope+() = func
and vfill_crypt_header_1831.getParentScope+() = func
and vpeer_id_1834.getParentScope+() = func
and vfrag_1835.getParentScope+() = func
and vmsdu_1839.getParentScope+() = func
and venctype_1842.getParentScope+() = func
and vfirst_hdr_1843.getParentScope+() = func
and vis_decrypted_1849.getParentScope+() = func
and vmulticast_check_1852.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
