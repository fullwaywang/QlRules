/**
 * @name wireshark-4a948427100b6c109f4ec7b4361f0d2aec5e5c3f-decompress
 * @id cpp/wireshark/4a948427100b6c109f4ec7b4361f0d2aec5e5c3f/decompress
 * @description wireshark-4a948427100b6c109f4ec7b4361f0d2aec5e5c3f-epan/dissectors/packet-blip.c-decompress CVE-2020-25866
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtvb_270, Variable vdecompress_buffer_295, VariableAccess target_0) {
		target_0.getTarget()=vdecompress_buffer_295
		and target_0.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("tvb_new_child_real_data")
		and target_0.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_270
}

predicate func_1(Function func, SizeofTypeOperator target_1) {
		target_1.getType() instanceof LongType
		and target_1.getValue()="16"
		and target_1.getEnclosingFunction() = func
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="16384"
		and not target_3.getValue()="0"
		and target_3.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("wmem_alloc")
		and target_3.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(0) instanceof FunctionCall
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, Literal target_4) {
		target_4.getValue()="16384"
		and not target_4.getValue()="1024"
		and target_4.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="avail_out"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(BlockStmt target_35, Function func) {
	exists(NotExpr target_5 |
		target_5.getOperand().(VariableAccess).getType().hasName("const decompress_result_t *")
		and target_5.getParent().(IfStmt).getThen()=target_35
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vtvb_270, Parameter voffset_270, RelationalOperation target_32, FunctionCall target_36) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_string")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("proto_tree *")
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_270
		and target_6.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_270
		and target_6.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("tvb_reported_length_remaining")
		and target_6.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_270
		and target_6.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_270
		and target_6.getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="<Error decompressing data>"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_32
		and target_36.getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_7(Parameter vpinfo_270, Variable vsaved_data_273, PointerFieldAccess target_37, FunctionCall target_38) {
	exists(IfStmt target_7 |
		target_7.getCondition().(PointerFieldAccess).getTarget().getName()="domain"
		and target_7.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsaved_data_273
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="domain"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("const decompress_result_t *")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info_format")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_270
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("proto_item *")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Unable to decompress message, got zlib error %d"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="code"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info_format")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_270
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("proto_item *")
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Unable to decompress message, buffer too small (%u Kb).  Please adjust in settings."
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("guint")
		and target_7.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_7.getElse().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_7.getElse().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_37
		and target_38.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_8(Parameter vpinfo_270, RelationalOperation target_33) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="domain"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("const decompress_result_t *")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info_format")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_270
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("proto_item *")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Unable to decompress message, got zlib error %d"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="code"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("const decompress_result_t *")
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info_format")
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_270
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("proto_item *")
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Unable to decompress message, buffer too small (%u Kb).  Please adjust in settings."
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("guint")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33)
}

*/
predicate func_11(Function func) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("wmem_packet_scope")
		and target_11.getEnclosingFunction() = func)
}

predicate func_14(Variable verr_301, BlockStmt target_39) {
	exists(EqualityOperation target_14 |
		target_14.getAnOperand().(VariableAccess).getTarget()=verr_301
		and target_14.getAnOperand() instanceof Literal
		and target_14.getParent().(IfStmt).getThen()=target_39)
}

predicate func_15(Parameter vpinfo_270, Variable verr_301, Variable vdata_to_save_1_316, RelationalOperation target_33, FunctionCall target_40, ExprStmt target_41, ExprStmt target_42, ExprStmt target_43) {
	exists(IfStmt target_15 |
		target_15.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("gboolean")
		and target_15.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verr_301
		and target_15.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-3"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="domain"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_to_save_1_316
		and target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info_format")
		and target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_270
		and target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("proto_item *")
		and target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Unable to decompress message, buffer too small (%u Kb).  Please adjust in settings."
		and target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("guint")
		and target_15.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="domain"
		and target_15.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("decompress_result_t *")
		and target_15.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="code"
		and target_15.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("decompress_result_t *")
		and target_15.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=verr_301
		and target_15.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info_format")
		and target_15.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_270
		and target_15.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("proto_item *")
		and target_15.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_15.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Unable to decompress message, got zlib error %d"
		and target_15.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=verr_301
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_15
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
		and target_40.getArgument(0).(VariableAccess).getLocation().isBefore(target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_41.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_42.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_43.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_16(Variable vdata_to_save_1_316, ExprStmt target_42, ExprStmt target_43) {
	exists(AssignExpr target_16 |
		target_16.getLValue().(PointerFieldAccess).getTarget().getName()="domain"
		and target_16.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_to_save_1_316
		and target_42.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_16.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_43.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_17(RelationalOperation target_33, Function func) {
	exists(ReturnStmt target_17 |
		target_17.getExpr().(Literal).getValue()="0"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_17
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(Parameter vpinfo_270, Variable vproto_blip, Variable verr_301, ExprStmt target_44, FunctionCall target_45, Function func) {
	exists(IfStmt target_18 |
		target_18.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verr_301
		and target_18.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verr_301
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-5"
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="domain"
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("gboolean")
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info_format")
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_270
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("proto_item *")
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Unable to decompress message, buffer too small (%u Kb).  Please adjust in settings."
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("guint")
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="domain"
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="code"
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=verr_301
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info_format")
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_270
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("proto_item *")
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Unable to decompress message, got zlib error %d"
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=verr_301
		and target_18.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("p_add_proto_data")
		and target_18.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("wmem_file_scope")
		and target_18.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_270
		and target_18.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vproto_blip
		and target_18.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_18.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("decompress_result_t *")
		and target_18.getThen().(BlockStmt).getStmt(4).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_18 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_18)
		and target_18.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_44.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_45.getArgument(2).(VariableAccess).getLocation().isBefore(target_18.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_19(Variable vdata_to_save_1_316, ExprStmt target_25, Function func) {
	exists(ExprStmt target_19 |
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_to_save_1_316
		and target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("Bytef *")
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_19 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_19)
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation()))
}

predicate func_21(Parameter vpinfo_270, Variable vproto_blip, Variable vdata_to_save_1_316, ExprStmt target_44, ExprStmt target_25, ExprStmt target_42, Function func) {
	exists(ExprStmt target_21 |
		target_21.getExpr().(FunctionCall).getTarget().hasName("p_add_proto_data")
		and target_21.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("wmem_file_scope")
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_270
		and target_21.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vproto_blip
		and target_21.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_21.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdata_to_save_1_316
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_21 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_21)
		and target_44.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_21.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_42.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_22(Parameter vpinfo_270, Variable vdecompressedChild_274, PointerFieldAccess target_37, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("add_new_data_source")
		and target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_270
		and target_22.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdecompressedChild_274
		and target_22.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Decompressed Payload"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_37
}

predicate func_23(Variable vdecompressedChild_274, PointerFieldAccess target_37, ReturnStmt target_23) {
		target_23.getExpr().(VariableAccess).getTarget()=vdecompressedChild_274
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_37
}

predicate func_24(PointerFieldAccess target_37, Function func, DeclStmt target_24) {
		target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_37
		and target_24.getEnclosingFunction() = func
}

predicate func_25(Parameter vpinfo_270, Variable vproto_blip, Variable vdata_to_save_1_316, Function func, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("p_add_proto_data")
		and target_25.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("wmem_file_scope")
		and target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_270
		and target_25.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vproto_blip
		and target_25.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_25.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdata_to_save_1_316
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_25
}

predicate func_26(Function func, FunctionCall target_26) {
		target_26.getTarget().hasName("wmem_file_scope")
		and target_26.getEnclosingFunction() = func
}

predicate func_27(Variable verr_301, BlockStmt target_35, VariableAccess target_27) {
		target_27.getTarget()=verr_301
		and target_27.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_27.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_35
}

predicate func_29(Variable verr_301, BlockStmt target_39, VariableAccess target_29) {
		target_29.getTarget()=verr_301
		and target_29.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_29.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_39
}

predicate func_31(Variable vdecompress_buffer_295, Variable vdata_to_save_1_316, VariableAccess target_31) {
		target_31.getTarget()=vdecompress_buffer_295
		and target_31.getParent().(AssignExpr).getRValue() = target_31
		and target_31.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_31.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_to_save_1_316
}

predicate func_32(Variable verr_301, BlockStmt target_35, RelationalOperation target_32) {
		 (target_32 instanceof GTExpr or target_32 instanceof LTExpr)
		and target_32.getLesserOperand().(VariableAccess).getTarget()=verr_301
		and target_32.getGreaterOperand() instanceof Literal
		and target_32.getParent().(IfStmt).getThen()=target_35
}

predicate func_33(Variable verr_301, BlockStmt target_39, RelationalOperation target_33) {
		 (target_33 instanceof GTExpr or target_33 instanceof LTExpr)
		and target_33.getLesserOperand().(VariableAccess).getTarget()=verr_301
		and target_33.getGreaterOperand() instanceof Literal
		and target_33.getParent().(IfStmt).getThen()=target_39
}

predicate func_35(BlockStmt target_35) {
		target_35.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_36(Parameter vtvb_270, Parameter voffset_270, FunctionCall target_36) {
		target_36.getTarget().hasName("tvb_get_ptr")
		and target_36.getArgument(0).(VariableAccess).getTarget()=vtvb_270
		and target_36.getArgument(1).(VariableAccess).getTarget()=voffset_270
}

predicate func_37(Parameter vpinfo_270, PointerFieldAccess target_37) {
		target_37.getTarget().getName()="visited"
		and target_37.getQualifier().(PointerFieldAccess).getTarget().getName()="fd"
		and target_37.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_270
}

predicate func_38(Parameter vtvb_270, Variable vsaved_data_273, FunctionCall target_38) {
		target_38.getTarget().hasName("tvb_new_child_real_data")
		and target_38.getArgument(0).(VariableAccess).getTarget()=vtvb_270
		and target_38.getArgument(1).(PointerFieldAccess).getTarget().getName()="buf"
		and target_38.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsaved_data_273
		and target_38.getArgument(2).(PointerFieldAccess).getTarget().getName()="size"
		and target_38.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsaved_data_273
		and target_38.getArgument(3).(PointerFieldAccess).getTarget().getName()="size"
		and target_38.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsaved_data_273
}

predicate func_39(BlockStmt target_39) {
		target_39.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_40(Parameter vpinfo_270, FunctionCall target_40) {
		target_40.getTarget().hasName("get_decompress_stream")
		and target_40.getArgument(0).(VariableAccess).getTarget()=vpinfo_270
}

predicate func_41(Variable verr_301, ExprStmt target_41) {
		target_41.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_301
		and target_41.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("inflate")
		and target_41.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="2"
}

predicate func_42(Variable vdata_to_save_1_316, ExprStmt target_42) {
		target_42.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_42.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_to_save_1_316
}

predicate func_43(Variable vdecompress_buffer_295, Variable vdata_to_save_1_316, ExprStmt target_43) {
		target_43.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_43.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_to_save_1_316
		and target_43.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdecompress_buffer_295
}

predicate func_44(Parameter vpinfo_270, ExprStmt target_44) {
		target_44.getExpr().(FunctionCall).getTarget().hasName("add_new_data_source")
		and target_44.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_270
		and target_44.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Decompressed Payload"
}

predicate func_45(Parameter vpinfo_270, Variable vproto_blip, FunctionCall target_45) {
		target_45.getTarget().hasName("p_get_proto_data")
		and target_45.getArgument(0).(FunctionCall).getTarget().hasName("wmem_file_scope")
		and target_45.getArgument(1).(VariableAccess).getTarget()=vpinfo_270
		and target_45.getArgument(2).(VariableAccess).getTarget()=vproto_blip
		and target_45.getArgument(3).(Literal).getValue()="0"
}

from Function func, Parameter vpinfo_270, Parameter vtvb_270, Parameter voffset_270, Variable vsaved_data_273, Variable vproto_blip, Variable vdecompressedChild_274, Variable vdecompress_buffer_295, Variable verr_301, Variable vdata_to_save_1_316, VariableAccess target_0, SizeofTypeOperator target_1, Literal target_3, Literal target_4, ExprStmt target_22, ReturnStmt target_23, DeclStmt target_24, ExprStmt target_25, FunctionCall target_26, VariableAccess target_27, VariableAccess target_29, VariableAccess target_31, RelationalOperation target_32, RelationalOperation target_33, BlockStmt target_35, FunctionCall target_36, PointerFieldAccess target_37, FunctionCall target_38, BlockStmt target_39, FunctionCall target_40, ExprStmt target_41, ExprStmt target_42, ExprStmt target_43, ExprStmt target_44, FunctionCall target_45
where
func_0(vtvb_270, vdecompress_buffer_295, target_0)
and func_1(func, target_1)
and func_3(func, target_3)
and func_4(func, target_4)
and not func_5(target_35, func)
and not func_6(vtvb_270, voffset_270, target_32, target_36)
and not func_7(vpinfo_270, vsaved_data_273, target_37, target_38)
and not func_11(func)
and not func_14(verr_301, target_39)
and not func_15(vpinfo_270, verr_301, vdata_to_save_1_316, target_33, target_40, target_41, target_42, target_43)
and not func_17(target_33, func)
and not func_18(vpinfo_270, vproto_blip, verr_301, target_44, target_45, func)
and not func_19(vdata_to_save_1_316, target_25, func)
and not func_21(vpinfo_270, vproto_blip, vdata_to_save_1_316, target_44, target_25, target_42, func)
and func_22(vpinfo_270, vdecompressedChild_274, target_37, target_22)
and func_23(vdecompressedChild_274, target_37, target_23)
and func_24(target_37, func, target_24)
and func_25(vpinfo_270, vproto_blip, vdata_to_save_1_316, func, target_25)
and func_26(func, target_26)
and func_27(verr_301, target_35, target_27)
and func_29(verr_301, target_39, target_29)
and func_31(vdecompress_buffer_295, vdata_to_save_1_316, target_31)
and func_32(verr_301, target_35, target_32)
and func_33(verr_301, target_39, target_33)
and func_35(target_35)
and func_36(vtvb_270, voffset_270, target_36)
and func_37(vpinfo_270, target_37)
and func_38(vtvb_270, vsaved_data_273, target_38)
and func_39(target_39)
and func_40(vpinfo_270, target_40)
and func_41(verr_301, target_41)
and func_42(vdata_to_save_1_316, target_42)
and func_43(vdecompress_buffer_295, vdata_to_save_1_316, target_43)
and func_44(vpinfo_270, target_44)
and func_45(vpinfo_270, vproto_blip, target_45)
and vpinfo_270.getType().hasName("packet_info *")
and vtvb_270.getType().hasName("tvbuff_t *")
and voffset_270.getType().hasName("gint")
and vsaved_data_273.getType().hasName("const slice_t *")
and vproto_blip.getType().hasName("int")
and vdecompressedChild_274.getType().hasName("tvbuff_t *")
and vdecompress_buffer_295.getType().hasName("Bytef *")
and verr_301.getType().hasName("int")
and vdata_to_save_1_316.getType().hasName("slice_t *")
and vpinfo_270.getParentScope+() = func
and vtvb_270.getParentScope+() = func
and voffset_270.getParentScope+() = func
and vsaved_data_273.getParentScope+() = func
and not vproto_blip.getParentScope+() = func
and vdecompressedChild_274.getParentScope+() = func
and vdecompress_buffer_295.getParentScope+() = func
and verr_301.getParentScope+() = func
and vdata_to_save_1_316.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
