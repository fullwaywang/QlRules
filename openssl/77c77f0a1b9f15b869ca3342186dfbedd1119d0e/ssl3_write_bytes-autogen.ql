/**
 * @name openssl-77c77f0a1b9f15b869ca3342186dfbedd1119d0e-ssl3_write_bytes
 * @id cpp/openssl/77c77f0a1b9f15b869ca3342186dfbedd1119d0e/ssl3-write-bytes
 * @description openssl-77c77f0a1b9f15b869ca3342186dfbedd1119d0e-ssl3_write_bytes CVE-2015-0290
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_624, Variable vwb_632) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="wbio"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_624
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BIO_test_flags")
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="wbio"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_624
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="8"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buf"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwb_632
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwb_632
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_1(Variable vwb_632, Variable vi_633) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vi_633
		and target_1.getGreaterOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buf"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwb_632
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwb_632
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_2(Parameter vtype_624, Parameter vs_624, Variable vbuf_626, Variable vtot_627, Variable vnw_628, Variable vi_633) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vi_633
		and target_2.getRValue().(FunctionCall).getTarget().hasName("ssl3_write_pending")
		and target_2.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_624
		and target_2.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtype_624
		and target_2.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_626
		and target_2.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtot_627
		and target_2.getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnw_628)
}

from Function func, Parameter vtype_624, Parameter vs_624, Variable vbuf_626, Variable vtot_627, Variable vnw_628, Variable vwb_632, Variable vi_633
where
not func_0(vs_624, vwb_632)
and func_1(vwb_632, vi_633)
and vs_624.getType().hasName("SSL *")
and func_2(vtype_624, vs_624, vbuf_626, vtot_627, vnw_628, vi_633)
and vbuf_626.getType().hasName("const unsigned char *")
and vtot_627.getType().hasName("int")
and vnw_628.getType().hasName("unsigned int")
and vwb_632.getType().hasName("SSL3_BUFFER *")
and vi_633.getType().hasName("int")
and vtype_624.getParentScope+() = func
and vs_624.getParentScope+() = func
and vbuf_626.getParentScope+() = func
and vtot_627.getParentScope+() = func
and vnw_628.getParentScope+() = func
and vwb_632.getParentScope+() = func
and vi_633.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
