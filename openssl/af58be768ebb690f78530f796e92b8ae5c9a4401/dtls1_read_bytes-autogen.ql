/**
 * @name openssl-af58be768ebb690f78530f796e92b8ae5c9a4401-dtls1_read_bytes
 * @id cpp/openssl/af58be768ebb690f78530f796e92b8ae5c9a4401/dtls1-read-bytes
 * @description openssl-af58be768ebb690f78530f796e92b8ae5c9a4401-dtls1_read_bytes 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vs_338, Variable val_341, Variable valert_level_703, Variable valert_descr_704, Variable vtmp_773) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="warn_alert"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_338
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=valert_descr_704
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alert_count"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_338
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="alert_count"
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_338
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="5"
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="258"
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="409"
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof GotoStmt
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=valert_descr_704
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="shutdown"
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="2"
		and target_2.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=valert_level_703
		and target_2.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof ArrayType
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rwstate"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_338
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fatal_alert"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=valert_descr_704
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="258"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1000"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=valert_descr_704
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BIO_snprintf")
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_773
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="16"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%d"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=valert_descr_704
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_add_error_data")
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SSL alert number "
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtmp_773
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="shutdown"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_338
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="2"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SSL_CTX_remove_session")
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="initial_ctx"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_338
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="session"
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_338
		and target_2.getElse().(IfStmt).getThen().(BlockStmt).getStmt(8).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_341
		and target_2.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="47"
		and target_2.getElse().(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getElse().(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_2.getElse().(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="258"
		and target_2.getElse().(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="246"
		and target_2.getElse().(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_2.getElse().(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_2.getElse().(IfStmt).getElse().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof RelationalOperation)
}

predicate func_10(Variable valert_level_703, Variable valert_descr_704) {
	exists(EqualityOperation target_10 |
		target_10.getAnOperand().(VariableAccess).getTarget()=valert_level_703
		and target_10.getAnOperand().(Literal).getValue()="1"
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="warn_alert"
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=valert_descr_704
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=valert_descr_704
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_11(Variable val_341, Variable vrr_343) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_341
		and target_11.getExpr().(AssignExpr).getRValue().(Literal).getValue()="10"
		and target_11.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getTarget().getName()="type"
		and target_11.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_343)
}

predicate func_12(Function func) {
	exists(GotoStmt target_12 |
		target_12.toString() = "goto ..."
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="alert_fragment_len"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Parameter vs_338, Variable vbio_679) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(VariableAccess).getTarget()=vbio_679
		and target_13.getRValue().(FunctionCall).getTarget().hasName("SSL_get_rbio")
		and target_13.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_338)
}

predicate func_14(Parameter vs_338, Variable valert_descr_704) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(PointerFieldAccess).getTarget().getName()="warn_alert"
		and target_14.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_14.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_338
		and target_14.getRValue().(VariableAccess).getTarget()=valert_descr_704)
}

predicate func_15(Variable vrr_343) {
	exists(AssignAddExpr target_15 |
		target_15.getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_15.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_343
		and target_15.getRValue().(UnaryMinusExpr).getValue()="-1")
}

predicate func_16(Variable vrr_343) {
	exists(AssignExpr target_16 |
		target_16.getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_16.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_343
		and target_16.getRValue().(Literal).getValue()="0")
}

from Function func, Parameter vs_338, Variable val_341, Variable vrr_343, Variable vbio_679, Variable valert_level_703, Variable valert_descr_704, Variable vtmp_773
where
not func_2(vs_338, val_341, valert_level_703, valert_descr_704, vtmp_773)
and func_10(valert_level_703, valert_descr_704)
and func_11(val_341, vrr_343)
and func_12(func)
and vs_338.getType().hasName("SSL *")
and func_13(vs_338, vbio_679)
and func_14(vs_338, valert_descr_704)
and val_341.getType().hasName("int")
and vrr_343.getType().hasName("SSL3_RECORD *")
and func_15(vrr_343)
and func_16(vrr_343)
and vbio_679.getType().hasName("BIO *")
and valert_level_703.getType().hasName("int")
and valert_descr_704.getType().hasName("int")
and vtmp_773.getType().hasName("char[16]")
and vs_338.getParentScope+() = func
and val_341.getParentScope+() = func
and vrr_343.getParentScope+() = func
and vbio_679.getParentScope+() = func
and valert_level_703.getParentScope+() = func
and valert_descr_704.getParentScope+() = func
and vtmp_773.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
