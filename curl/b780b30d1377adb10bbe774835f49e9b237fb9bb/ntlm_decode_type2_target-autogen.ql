/**
 * @name curl-b780b30d1377adb10bbe774835f49e9b237fb9bb-ntlm_decode_type2_target
 * @id cpp/curl/b780b30d1377adb10bbe774835f49e9b237fb9bb/ntlm-decode-type2-target
 * @description curl-b780b30d1377adb10bbe774835f49e9b237fb9bb-ntlm_decode_type2_target CVE-2018-16890
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_171, Variable vtarget_info_offset_175, Parameter vdata_169) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_171
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="48"
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_169
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer\n")
}

predicate func_1(Parameter vsize_171, Variable vtarget_info_len_174, Variable vtarget_info_offset_175, Parameter vdata_169) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtarget_info_len_174
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vsize_171
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="48"
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_169
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer\n")
}

predicate func_2(Variable vCurl_cmalloc, Parameter vbuffer_170, Parameter vsize_171, Parameter vntlm_172, Variable vtarget_info_len_174, Variable vtarget_info_offset_175, Parameter vdata_169) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vsize_171
		and target_2.getLesserOperand().(Literal).getValue()="48"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtarget_info_len_174
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_read16_le")
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_170
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="40"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_read32_le")
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_170
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="44"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtarget_info_len_174
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="48"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_169
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer\n"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="target_info"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vntlm_172
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_cmalloc
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vtarget_info_len_174)
}

predicate func_3(Parameter vbuffer_170, Variable vtarget_info_offset_175) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_3.getRValue().(FunctionCall).getTarget().hasName("Curl_read32_le")
		and target_3.getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_170
		and target_3.getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="44")
}

from Function func, Variable vCurl_cmalloc, Parameter vbuffer_170, Parameter vsize_171, Parameter vntlm_172, Variable vtarget_info_len_174, Variable vtarget_info_offset_175, Parameter vdata_169
where
not func_0(vsize_171, vtarget_info_offset_175, vdata_169)
and func_1(vsize_171, vtarget_info_len_174, vtarget_info_offset_175, vdata_169)
and vsize_171.getType().hasName("size_t")
and func_2(vCurl_cmalloc, vbuffer_170, vsize_171, vntlm_172, vtarget_info_len_174, vtarget_info_offset_175, vdata_169)
and vntlm_172.getType().hasName("ntlmdata *")
and vtarget_info_len_174.getType().hasName("unsigned short")
and vtarget_info_offset_175.getType().hasName("unsigned int")
and func_3(vbuffer_170, vtarget_info_offset_175)
and vdata_169.getType().hasName("Curl_easy *")
and not vCurl_cmalloc.getParentScope+() = func
and vbuffer_170.getParentScope+() = func
and vsize_171.getParentScope+() = func
and vntlm_172.getParentScope+() = func
and vtarget_info_len_174.getParentScope+() = func
and vtarget_info_offset_175.getParentScope+() = func
and vdata_169.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
