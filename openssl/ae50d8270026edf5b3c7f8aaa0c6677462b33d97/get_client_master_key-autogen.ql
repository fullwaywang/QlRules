/**
 * @name openssl-ae50d8270026edf5b3c7f8aaa0c6677462b33d97-get_client_master_key
 * @id cpp/openssl/ae50d8270026edf5b3c7f8aaa0c6677462b33d97/get-client-master-key
 * @description openssl-ae50d8270026edf5b3c7f8aaa0c6677462b33d97-get_client_master_key CVE-2016-0703
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vek_375) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vek_375
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(Literal).getValue()="8")
}

predicate func_2(Variable vek_375) {
	exists(VariableAccess target_2 |
		target_2.getTarget()=vek_375)
}

predicate func_4(Function func) {
	exists(VariableDeclarationEntry target_4 |
		target_4.getType() instanceof IntType
		and target_4.getDeclaration().getParentScope+() = func)
}

predicate func_8(Function func) {
	exists(DeclStmt target_8 |
		target_8.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof ArrayType
		and func.getEntryPoint().(BlockStmt).getStmt(7)=target_8)
}

predicate func_9(Function func) {
	exists(DeclStmt target_9 |
		target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof UnsignedCharType
		and func.getEntryPoint().(BlockStmt).getStmt(8)=target_9)
}

predicate func_10(Function func) {
	exists(DeclStmt target_10 |
		target_10.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Size_t
		and func.getEntryPoint().(BlockStmt).getStmt(9)=target_10)
}

predicate func_11(Function func) {
	exists(AssignExpr target_11 |
		target_11.getLValue().(VariableAccess).getType().hasName("unsigned int")
		and target_11.getRValue() instanceof FunctionCall
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(AssignExpr target_12 |
		target_12.getLValue().(VariableAccess).getType().hasName("unsigned int")
		and target_12.getRValue().(VariableAccess).getType().hasName("unsigned int")
		and target_12.getEnclosingFunction() = func)
}

predicate func_16(Variable vi_374) {
	exists(AssignExpr target_16 |
		target_16.getLValue().(VariableAccess).getType().hasName("unsigned char")
		and target_16.getRValue().(FunctionCall).getTarget().hasName("constant_time_eq_int_8")
		and target_16.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_374
		and target_16.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("unsigned int"))
}

predicate func_17(Variable vp_377, Function func) {
	exists(ForStmt target_17 |
		target_17.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_17.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_17.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_17.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("size_t")
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_377
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof ValueFieldAccess
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("constant_time_select_8")
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("unsigned char")
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_377
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("unsigned char[48]")
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(35)=target_17 or func.getEntryPoint().(BlockStmt).getStmt(35).getFollowingStmt()=target_17))
}

predicate func_24(Variable vp_377, Function func) {
	exists(ExprStmt target_24 |
		target_24.getExpr().(FunctionCall).getTarget().hasName("OPENSSL_cleanse")
		and target_24.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_377
		and target_24.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("unsigned int")
		and (func.getEntryPoint().(BlockStmt).getStmt(38)=target_24 or func.getEntryPoint().(BlockStmt).getStmt(38).getFollowingStmt()=target_24))
}

predicate func_25(Parameter vs_372, Variable vis_export_374, Variable vek_375) {
	exists(BitwiseAndExpr target_25 |
		target_25.getLeftOperand().(PointerFieldAccess).getTarget().getName()="algorithm2"
		and target_25.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cipher"
		and target_25.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_25.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_372
		and target_25.getRightOperand().(Literal).getValue()="2"
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_export_374
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vek_375
		and target_25.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="8")
}

predicate func_26(Parameter vs_372) {
	exists(ValueFieldAccess target_26 |
		target_26.getTarget().getName()="clear"
		and target_26.getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_26.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s2"
		and target_26.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_372)
}

predicate func_28(Variable vc_379) {
	exists(FunctionCall target_28 |
		target_28.getTarget().hasName("EVP_CIPHER_key_length")
		and target_28.getArgument(0).(VariableAccess).getTarget()=vc_379)
}

predicate func_29(Parameter vs_372) {
	exists(ExprStmt target_29 |
		target_29.getExpr().(FunctionCall).getTarget().hasName("ssl2_return_error")
		and target_29.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_372
		and target_29.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_29.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof LogicalOrExpr)
}

predicate func_30(Function func) {
	exists(ReturnStmt target_30 |
		target_30.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_30.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof LogicalOrExpr
		and target_30.getEnclosingFunction() = func)
}

predicate func_31(Parameter vs_372) {
	exists(ValueFieldAccess target_31 |
		target_31.getTarget().getName()="enc"
		and target_31.getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_31.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s2"
		and target_31.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_372)
}

predicate func_34(Function func) {
	exists(ExprStmt target_34 |
		target_34.getExpr().(FunctionCall).getTarget().hasName("ERR_clear_error")
		and target_34.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof LogicalOrExpr
		and target_34.getEnclosingFunction() = func)
}

predicate func_38(Parameter vs_372, Variable vi_374) {
	exists(PointerFieldAccess target_38 |
		target_38.getTarget().getName()="master_key_length"
		and target_38.getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_38.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_372
		and target_38.getParent().(AssignExpr).getLValue() = target_38
		and target_38.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vi_374)
}

predicate func_39(Function func) {
	exists(Literal target_39 |
		target_39.getValue()="0"
		and target_39.getEnclosingFunction() = func)
}

predicate func_42(Variable vis_export_374, Variable vek_375) {
	exists(LogicalOrExpr target_42 |
		target_42.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vis_export_374
		and target_42.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof ValueFieldAccess
		and target_42.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_42.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_export_374
		and target_42.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand() instanceof ValueFieldAccess
		and target_42.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vek_375
		and target_42.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_42.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_42.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_42.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_42.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_42.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_42.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_42.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_43(Parameter vs_372, Variable vis_export_374, Variable vek_375, Variable vc_379) {
	exists(LogicalOrExpr target_43 |
		target_43.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_export_374
		and target_43.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="enc"
		and target_43.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_43.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s2"
		and target_43.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_372
		and target_43.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vek_375
		and target_43.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vis_export_374
		and target_43.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof ValueFieldAccess
		and target_43.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("EVP_CIPHER_key_length")
		and target_43.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_379
		and target_43.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_43.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_43.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_43.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_43.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_43.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_43.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_45(Variable vis_export_374, Variable vi_374, Variable vek_375, Variable vc_379) {
	exists(LogicalOrExpr target_45 |
		target_45.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_374
		and target_45.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_45.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vis_export_374
		and target_45.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_374
		and target_45.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("EVP_CIPHER_key_length")
		and target_45.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_379
		and target_45.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_export_374
		and target_45.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_374
		and target_45.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vek_375
		and target_45.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_45.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vis_export_374
		and target_45.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_374
		and target_45.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vek_375
		and target_45.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_374
		and target_45.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("EVP_CIPHER_key_length"))
}

predicate func_51(Variable vis_export_374, Variable vi_374, Variable vc_379, Function func) {
	exists(IfStmt target_51 |
		target_51.getCondition().(VariableAccess).getTarget()=vis_export_374
		and target_51.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_374
		and target_51.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("EVP_CIPHER_key_length")
		and target_51.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_379
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_51)
}

predicate func_53(Variable vi_374, Function func) {
	exists(IfStmt target_53 |
		target_53.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_374
		and target_53.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="48"
		and target_53.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_53.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_53.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_53.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_53.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BitwiseOrExpr).getValue()="68"
		and target_53.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_53.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_53.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_53)
}

predicate func_55(Parameter vs_372, Variable vi_374) {
	exists(AssignExpr target_55 |
		target_55.getLValue().(PointerFieldAccess).getTarget().getName()="master_key_length"
		and target_55.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_55.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_372
		and target_55.getRValue().(VariableAccess).getTarget()=vi_374)
}

predicate func_57(Parameter vs_372) {
	exists(PointerFieldAccess target_57 |
		target_57.getTarget().getName()="master_key"
		and target_57.getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_57.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_372)
}

predicate func_58(Parameter vs_372, Variable vi_374, Variable vp_377) {
	exists(FunctionCall target_58 |
		target_58.getTarget().hasName("memcpy")
		and target_58.getArgument(0).(PointerFieldAccess).getTarget().getName()="master_key"
		and target_58.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_58.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_372
		and target_58.getArgument(1).(VariableAccess).getTarget()=vp_377
		and target_58.getArgument(2).(VariableAccess).getTarget()=vi_374)
}

from Function func, Parameter vs_372, Variable vis_export_374, Variable vi_374, Variable vek_375, Variable vp_377, Variable vc_379
where
func_0(vek_375)
and func_2(vek_375)
and func_4(func)
and not func_8(func)
and not func_9(func)
and not func_10(func)
and not func_11(func)
and not func_12(func)
and not func_16(vi_374)
and not func_17(vp_377, func)
and not func_24(vp_377, func)
and func_25(vs_372, vis_export_374, vek_375)
and func_26(vs_372)
and func_28(vc_379)
and func_29(vs_372)
and func_30(func)
and func_31(vs_372)
and func_34(func)
and func_38(vs_372, vi_374)
and func_39(func)
and func_42(vis_export_374, vek_375)
and func_43(vs_372, vis_export_374, vek_375, vc_379)
and func_45(vis_export_374, vi_374, vek_375, vc_379)
and func_51(vis_export_374, vi_374, vc_379, func)
and func_53(vi_374, func)
and func_55(vs_372, vi_374)
and vs_372.getType().hasName("SSL *")
and func_57(vs_372)
and vis_export_374.getType().hasName("int")
and vi_374.getType().hasName("int")
and vp_377.getType().hasName("unsigned char *")
and func_58(vs_372, vi_374, vp_377)
and vc_379.getType().hasName("const EVP_CIPHER *")
and vs_372.getParentScope+() = func
and vis_export_374.getParentScope+() = func
and vi_374.getParentScope+() = func
and vek_375.getParentScope+() = func
and vp_377.getParentScope+() = func
and vc_379.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
