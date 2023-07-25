/**
 * @name openssl-96db9023b881d7cd9f379b0c154650d6c108e9a3-dtls1_process_heartbeat
 * @id cpp/openssl/96db9023b881d7cd9f379b0c154650d6c108e9a3/dtls1-process-heartbeat
 * @description openssl-96db9023b881d7cd9f379b0c154650d6c108e9a3-dtls1_process_heartbeat CVE-2014-0160
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpayload_1459) {
	exists(Literal target_0 |
		target_0.getValue()="3"
		and not target_0.getValue()="2"
		and target_0.getParent().(AddExpr).getParent().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vpayload_1459)
}

predicate func_1(Variable vpadding_1460) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vpadding_1460)
}

predicate func_3(Variable vpayload_1459) {
	exists(VariableAccess target_3 |
		target_3.getTarget()=vpayload_1459)
}

predicate func_5(Parameter vs_1455) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(AddExpr).getValue()="19"
		and target_5.getLesserOperand().(ValueFieldAccess).getTarget().getName()="length"
		and target_5.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rrec"
		and target_5.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_5.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_5.getParent().(IfStmt).getThen() instanceof ReturnStmt)
}

predicate func_10(Parameter vs_1455, Variable vpl_1457, Variable vpayload_1459, Variable vpadding_1460, Variable vbuffer_1474, Variable vbp_1474, Variable vr_1475, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition() instanceof EqualityOperation
		and target_10.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CharPointerType
		and target_10.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(1).(VariableDeclarationEntry).getType() instanceof CharPointerType
		and target_10.getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof AddExpr
		and target_10.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_10.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="16384"
		and target_10.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffer_1474
		and target_10.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CRYPTO_malloc")
		and target_10.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("unsigned int")
		and target_10.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_10.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal
		and target_10.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbp_1474
		and target_10.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbuffer_1474
		and target_10.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vbp_1474
		and target_10.getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and target_10.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vbp_1474
		and target_10.getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_10.getThen().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_10.getThen().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbp_1474
		and target_10.getThen().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpl_1457
		and target_10.getThen().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpayload_1459
		and target_10.getThen().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vbp_1474
		and target_10.getThen().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vpayload_1459
		and target_10.getThen().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("RAND_pseudo_bytes")
		and target_10.getThen().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbp_1474
		and target_10.getThen().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpadding_1460
		and target_10.getThen().(BlockStmt).getStmt(11).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_1475
		and target_10.getThen().(BlockStmt).getStmt(11).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dtls1_write_bytes")
		and target_10.getThen().(BlockStmt).getStmt(11).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1455
		and target_10.getThen().(BlockStmt).getStmt(11).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="24"
		and target_10.getThen().(BlockStmt).getStmt(11).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffer_1474
		and target_10.getThen().(BlockStmt).getStmt(11).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("unsigned int")
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getCondition() instanceof LogicalAndExpr
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="msg_callback"
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(Literal).getValue()="1"
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="version"
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(Literal).getValue()="24"
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vbuffer_1474
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(4).(VariableAccess).getType().hasName("unsigned int")
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(5).(VariableAccess).getTarget()=vs_1455
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="msg_callback_arg"
		and target_10.getThen().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_10.getThen().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_10.getThen().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_1474
		and target_10.getThen().(BlockStmt).getStmt(14).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vr_1475
		and target_10.getThen().(BlockStmt).getStmt(14).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(14).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vr_1475
		and target_10.getElse() instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_10))
}

predicate func_18(Parameter vs_1455, Variable vbuffer_1474, Variable vr_1475) {
	exists(LogicalAndExpr target_18 |
		target_18.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vr_1475
		and target_18.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_18.getAnOperand().(PointerFieldAccess).getTarget().getName()="msg_callback"
		and target_18.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="msg_callback"
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(Literal).getValue()="1"
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="version"
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(Literal).getValue()="24"
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vbuffer_1474
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(4) instanceof AddExpr
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(5).(VariableAccess).getTarget()=vs_1455
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="msg_callback_arg"
		and target_18.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455)
}

predicate func_19(Parameter vs_1455, Variable vpl_1457, Variable vhbtype_1458, Variable vpayload_1459, Variable vseq_1506) {
	exists(IfStmt target_19 |
		target_19.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhbtype_1458
		and target_19.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_19.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof IntType
		and target_19.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vseq_1506
		and target_19.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vpl_1457
		and target_19.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_19.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpayload_1459
		and target_19.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="18"
		and target_19.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vseq_1506
		and target_19.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tlsext_hb_seq"
		and target_19.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_19.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dtls1_stop_timer")
		and target_19.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1455
		and target_19.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tlsext_hb_seq"
		and target_19.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_hb_pending"
		and target_19.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_19.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhbtype_1458
		and target_19.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1")
}

predicate func_21(Parameter vs_1455, Variable vpayload_1459, Variable vpadding_1460, Variable vbuffer_1474) {
	exists(AddExpr target_21 |
		target_21.getAnOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_21.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vpayload_1459
		and target_21.getAnOperand().(VariableAccess).getTarget()=vpadding_1460
		and target_21.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="msg_callback"
		and target_21.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_21.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(Literal).getValue()="1"
		and target_21.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="version"
		and target_21.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_21.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(2).(Literal).getValue()="24"
		and target_21.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vbuffer_1474
		and target_21.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(5).(VariableAccess).getTarget()=vs_1455
		and target_21.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="msg_callback_arg"
		and target_21.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455)
}

predicate func_22(Parameter vs_1455) {
	exists(VariableCall target_22 |
		target_22.getExpr().(PointerFieldAccess).getTarget().getName()="msg_callback"
		and target_22.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_22.getArgument(0).(Literal).getValue()="0"
		and target_22.getArgument(1).(PointerFieldAccess).getTarget().getName()="version"
		and target_22.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_22.getArgument(2).(Literal).getValue()="24"
		and target_22.getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="data"
		and target_22.getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rrec"
		and target_22.getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_22.getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_22.getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_22.getArgument(4).(ValueFieldAccess).getTarget().getName()="length"
		and target_22.getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rrec"
		and target_22.getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_22.getArgument(4).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455
		and target_22.getArgument(5).(VariableAccess).getTarget()=vs_1455
		and target_22.getArgument(6).(PointerFieldAccess).getTarget().getName()="msg_callback_arg"
		and target_22.getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1455)
}

predicate func_23(Parameter vs_1455, Variable vpayload_1459, Variable vpadding_1460, Variable vbuffer_1474, Variable vr_1475) {
	exists(AssignExpr target_23 |
		target_23.getLValue().(VariableAccess).getTarget()=vr_1475
		and target_23.getRValue().(FunctionCall).getTarget().hasName("dtls1_write_bytes")
		and target_23.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1455
		and target_23.getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="24"
		and target_23.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffer_1474
		and target_23.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_23.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vpayload_1459
		and target_23.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vpadding_1460)
}

from Function func, Parameter vs_1455, Variable vpl_1457, Variable vhbtype_1458, Variable vpayload_1459, Variable vpadding_1460, Variable vbuffer_1474, Variable vbp_1474, Variable vr_1475, Variable vseq_1506
where
func_0(vpayload_1459)
and func_1(vpadding_1460)
and func_3(vpayload_1459)
and not func_5(vs_1455)
and not func_10(vs_1455, vpl_1457, vpayload_1459, vpadding_1460, vbuffer_1474, vbp_1474, vr_1475, func)
and func_18(vs_1455, vbuffer_1474, vr_1475)
and func_19(vs_1455, vpl_1457, vhbtype_1458, vpayload_1459, vseq_1506)
and func_21(vs_1455, vpayload_1459, vpadding_1460, vbuffer_1474)
and vs_1455.getType().hasName("SSL *")
and func_22(vs_1455)
and func_23(vs_1455, vpayload_1459, vpadding_1460, vbuffer_1474, vr_1475)
and vpl_1457.getType().hasName("unsigned char *")
and vhbtype_1458.getType().hasName("unsigned short")
and vpayload_1459.getType().hasName("unsigned int")
and vpadding_1460.getType().hasName("unsigned int")
and vbuffer_1474.getType().hasName("unsigned char *")
and vbp_1474.getType().hasName("unsigned char *")
and vr_1475.getType().hasName("int")
and vseq_1506.getType().hasName("unsigned int")
and vs_1455.getParentScope+() = func
and vpl_1457.getParentScope+() = func
and vhbtype_1458.getParentScope+() = func
and vpayload_1459.getParentScope+() = func
and vpadding_1460.getParentScope+() = func
and vbuffer_1474.getParentScope+() = func
and vbp_1474.getParentScope+() = func
and vr_1475.getParentScope+() = func
and vseq_1506.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
