/**
 * @name openjpeg-f8796711e8d8e004d8b73929f0ff87c83abf0c76-opj_t2_encode_packets
 * @id cpp/openjpeg/f8796711e8d8e004d8b73929f0ff87c83abf0c76/opj-t2-encode-packets
 * @description openjpeg-f8796711e8d8e004d8b73929f0ff87c83abf0c76-src/lib/openjp2/t2.c-opj_t2_encode_packets CVE-2014-7945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_current_pi_217, ExprStmt target_8, FunctionCall target_9) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prg"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="poc"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_current_pi_217
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_1(EqualityOperation target_10, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_1.getEnclosingFunction() = func)
}

*/
predicate func_2(Variable vl_pi_216, Variable vl_current_pi_217, Variable vl_nb_pocs_223, EqualityOperation target_10, ExprStmt target_11, ExprStmt target_4, ExprStmt target_12, ExprStmt target_13) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prg"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="poc"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_current_pi_217
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_pi_destroy")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_pi_216
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_nb_pocs_223
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_12.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_3(Variable vl_pi_216, Variable vl_nb_pocs_223, ExprStmt target_13, ExprStmt target_7, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("opj_pi_destroy")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_pi_216
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_nb_pocs_223
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_3)
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vp_tile_no_200, Parameter vp_tp_num_207, Parameter vp_tp_pos_208, Parameter vp_pino_209, Parameter vp_t2_mode_210, Variable vl_pi_216, Variable vl_cp_219, EqualityOperation target_10, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("opj_pi_create_encode")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_pi_216
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_cp_219
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vp_tile_no_200
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp_pino_209
		and target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vp_tp_num_207
		and target_4.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vp_tp_pos_208
		and target_4.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vp_t2_mode_210
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_5(Parameter vp_pino_209, Variable vl_pi_216, Variable vl_current_pi_217, EqualityOperation target_10, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_current_pi_217
		and target_5.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vl_pi_216
		and target_5.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vp_pino_209
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_6(Parameter vp_maxlayers_202, Parameter vp_max_len_205, Parameter vcstr_info_206, Variable vl_current_data_212, Variable vl_nb_bytes_213, Variable vl_current_pi_217, EqualityOperation target_10, WhileStmt target_6) {
		target_6.getCondition().(FunctionCall).getTarget().hasName("opj_pi_next")
		and target_6.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_current_pi_217
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="layno"
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_current_pi_217
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_maxlayers_202
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_nb_bytes_213
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("opj_t2_encode_packet")
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_current_data_212
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vl_nb_bytes_213
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vp_max_len_205
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vl_nb_bytes_213
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vl_nb_bytes_213
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(VariableAccess).getTarget()=vcstr_info_206
		and target_6.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="packno"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_7(Variable vl_pi_216, Variable vl_nb_pocs_223, Function func, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("opj_pi_destroy")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_pi_216
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_nb_pocs_223
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vl_pi_216, Variable vl_current_pi_217, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_current_pi_217
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vl_pi_216
}

predicate func_9(Variable vl_current_pi_217, FunctionCall target_9) {
		target_9.getTarget().hasName("opj_pi_next")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vl_current_pi_217
}

predicate func_10(Parameter vp_t2_mode_210, EqualityOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vp_t2_mode_210
}

predicate func_11(Variable vl_pi_216, Variable vl_nb_pocs_223, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("opj_pi_destroy")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_pi_216
		and target_11.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_nb_pocs_223
}

predicate func_12(Variable vl_current_pi_217, ExprStmt target_12) {
		target_12.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_current_pi_217
}

predicate func_13(Variable vl_pi_216, Variable vl_nb_pocs_223, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("opj_pi_destroy")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_pi_216
		and target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_nb_pocs_223
}

from Function func, Parameter vp_tile_no_200, Parameter vp_maxlayers_202, Parameter vp_max_len_205, Parameter vcstr_info_206, Parameter vp_tp_num_207, Parameter vp_tp_pos_208, Parameter vp_pino_209, Parameter vp_t2_mode_210, Variable vl_current_data_212, Variable vl_nb_bytes_213, Variable vl_pi_216, Variable vl_current_pi_217, Variable vl_cp_219, Variable vl_nb_pocs_223, ExprStmt target_4, ExprStmt target_5, WhileStmt target_6, ExprStmt target_7, ExprStmt target_8, FunctionCall target_9, EqualityOperation target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13
where
not func_0(vl_current_pi_217, target_8, target_9)
and not func_2(vl_pi_216, vl_current_pi_217, vl_nb_pocs_223, target_10, target_11, target_4, target_12, target_13)
and not func_3(vl_pi_216, vl_nb_pocs_223, target_13, target_7, func)
and func_4(vp_tile_no_200, vp_tp_num_207, vp_tp_pos_208, vp_pino_209, vp_t2_mode_210, vl_pi_216, vl_cp_219, target_10, target_4)
and func_5(vp_pino_209, vl_pi_216, vl_current_pi_217, target_10, target_5)
and func_6(vp_maxlayers_202, vp_max_len_205, vcstr_info_206, vl_current_data_212, vl_nb_bytes_213, vl_current_pi_217, target_10, target_6)
and func_7(vl_pi_216, vl_nb_pocs_223, func, target_7)
and func_8(vl_pi_216, vl_current_pi_217, target_8)
and func_9(vl_current_pi_217, target_9)
and func_10(vp_t2_mode_210, target_10)
and func_11(vl_pi_216, vl_nb_pocs_223, target_11)
and func_12(vl_current_pi_217, target_12)
and func_13(vl_pi_216, vl_nb_pocs_223, target_13)
and vp_tile_no_200.getType().hasName("OPJ_UINT32")
and vp_maxlayers_202.getType().hasName("OPJ_UINT32")
and vp_max_len_205.getType().hasName("OPJ_UINT32")
and vcstr_info_206.getType().hasName("opj_codestream_info_t *")
and vp_tp_num_207.getType().hasName("OPJ_UINT32")
and vp_tp_pos_208.getType().hasName("OPJ_INT32")
and vp_pino_209.getType().hasName("OPJ_UINT32")
and vp_t2_mode_210.getType().hasName("J2K_T2_MODE")
and vl_current_data_212.getType().hasName("OPJ_BYTE *")
and vl_nb_bytes_213.getType().hasName("OPJ_UINT32")
and vl_pi_216.getType().hasName("opj_pi_iterator_t *")
and vl_current_pi_217.getType().hasName("opj_pi_iterator_t *")
and vl_cp_219.getType().hasName("opj_cp_t *")
and vl_nb_pocs_223.getType().hasName("OPJ_UINT32")
and vp_tile_no_200.getParentScope+() = func
and vp_maxlayers_202.getParentScope+() = func
and vp_max_len_205.getParentScope+() = func
and vcstr_info_206.getParentScope+() = func
and vp_tp_num_207.getParentScope+() = func
and vp_tp_pos_208.getParentScope+() = func
and vp_pino_209.getParentScope+() = func
and vp_t2_mode_210.getParentScope+() = func
and vl_current_data_212.getParentScope+() = func
and vl_nb_bytes_213.getParentScope+() = func
and vl_pi_216.getParentScope+() = func
and vl_current_pi_217.getParentScope+() = func
and vl_cp_219.getParentScope+() = func
and vl_nb_pocs_223.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
