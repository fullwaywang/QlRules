/**
 * @name openssl-0042fb5fd1c9d257d713b15a1f45da05cf5c1c87-OBJ_obj2txt
 * @id cpp/openssl/0042fb5fd1c9d257d713b15a1f45da05cf5c1c87/OBJ-obj2txt
 * @description openssl-0042fb5fd1c9d257d713b15a1f45da05cf5c1c87-OBJ_obj2txt CVE-2014-3508
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vbuf_466, Parameter vbuf_len_466) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuf_len_466
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbuf_466
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vbuf_466)
}

predicate func_7(Variable vfirst_468) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfirst_468
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vfirst_468)
}

predicate func_8(Variable vi_468, Variable vfirst_468, Variable vuse_bn_468, Variable vl_470) {
	exists(IfStmt target_8 |
		target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vl_470
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="80"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_468
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vuse_bn_468
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_sub_word")
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vl_470
		and target_8.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="80"
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_468
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vl_470
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="40"
		and target_8.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vl_470
		and target_8.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vi_468
		and target_8.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="40"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vfirst_468)
}

predicate func_12(Variable vn_468, Variable vfirst_468) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vn_468
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vfirst_468)
}

predicate func_13(Variable vuse_bn_468) {
	exists(DeclStmt target_13 |
		target_13.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CharPointerType
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vuse_bn_468)
}

predicate func_14(Variable vuse_bn_468, Variable vbl_469, Variable vbndec_567) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbndec_567
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_bn2dec")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbl_469
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vuse_bn_468)
}

predicate func_15(Variable vuse_bn_468, Variable vbndec_567) {
	exists(IfStmt target_15 |
		target_15.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vbndec_567
		and target_15.getThen().(GotoStmt).toString() = "goto ..."
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vuse_bn_468)
}

predicate func_16(Variable vi_468, Variable vuse_bn_468, Variable vbndec_567) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_468
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbndec_567
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vuse_bn_468)
}

predicate func_18(Parameter vbuf_466, Parameter vbuf_len_466) {
	exists(ExprStmt target_18 |
		target_18.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vbuf_466
		and target_18.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="46"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuf_len_466
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0")
}

predicate func_20(Parameter vbuf_466, Parameter vbuf_len_466, Variable vbndec_567) {
	exists(ExprStmt target_20 |
		target_20.getExpr().(FunctionCall).getTarget().hasName("BUF_strlcpy")
		and target_20.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_466
		and target_20.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbndec_567
		and target_20.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuf_len_466
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vbuf_466)
}

predicate func_21(Parameter vbuf_466, Parameter vbuf_len_466, Variable vi_468) {
	exists(IfStmt target_21 |
		target_21.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_468
		and target_21.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_len_466
		and target_21.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vbuf_466
		and target_21.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vbuf_len_466
		and target_21.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_len_466
		and target_21.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_21.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vbuf_466
		and target_21.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vi_468
		and target_21.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vbuf_len_466
		and target_21.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vi_468
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vbuf_466)
}

predicate func_23(Variable vi_468, Variable vn_468, Variable vuse_bn_468) {
	exists(ExprStmt target_23 |
		target_23.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vn_468
		and target_23.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vi_468
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vuse_bn_468)
}

predicate func_24(Variable vuse_bn_468, Variable vbndec_567) {
	exists(ExprStmt target_24 |
		target_24.getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_24.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbndec_567
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vuse_bn_468)
}

predicate func_25(Parameter vbuf_466, Parameter vbuf_len_466, Variable vi_468, Variable vn_468, Variable vuse_bn_468, Variable vl_470, Variable vtbuf_472) {
	exists(BlockStmt target_25 |
		target_25.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BIO_snprintf")
		and target_25.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtbuf_472
		and target_25.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="37"
		and target_25.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()=".%lu"
		and target_25.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vl_470
		and target_25.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_468
		and target_25.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_25.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtbuf_472
		and target_25.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vbuf_466
		and target_25.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuf_len_466
		and target_25.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_25.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BUF_strlcpy")
		and target_25.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_466
		and target_25.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtbuf_472
		and target_25.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuf_len_466
		and target_25.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_468
		and target_25.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuf_len_466
		and target_25.getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vn_468
		and target_25.getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vi_468
		and target_25.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_470
		and target_25.getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_25.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vuse_bn_468)
}

predicate func_29(Parameter vbuf_466, Parameter vbuf_len_466, Variable vs_482) {
	exists(FunctionCall target_29 |
		target_29.getTarget().hasName("BUF_strlcpy")
		and target_29.getArgument(0).(VariableAccess).getTarget()=vbuf_466
		and target_29.getArgument(1).(VariableAccess).getTarget()=vs_482
		and target_29.getArgument(2).(VariableAccess).getTarget()=vbuf_len_466)
}

predicate func_30(Parameter vbuf_466) {
	exists(AssignExpr target_30 |
		target_30.getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vbuf_466
		and target_30.getRValue().(CharLiteral).getValue()="46")
}

predicate func_32(Parameter vbuf_len_466) {
	exists(PostfixDecrExpr target_32 |
		target_32.getOperand().(VariableAccess).getTarget()=vbuf_len_466)
}

from Function func, Parameter vbuf_466, Parameter vbuf_len_466, Parameter va_466, Variable vi_468, Variable vn_468, Variable vfirst_468, Variable vuse_bn_468, Variable vbl_469, Variable vl_470, Variable vtbuf_472, Variable vs_482, Variable vbndec_567
where
not func_2(vbuf_466, vbuf_len_466)
and func_7(vfirst_468)
and func_8(vi_468, vfirst_468, vuse_bn_468, vl_470)
and func_12(vn_468, vfirst_468)
and func_13(vuse_bn_468)
and func_14(vuse_bn_468, vbl_469, vbndec_567)
and func_15(vuse_bn_468, vbndec_567)
and func_16(vi_468, vuse_bn_468, vbndec_567)
and func_18(vbuf_466, vbuf_len_466)
and func_20(vbuf_466, vbuf_len_466, vbndec_567)
and func_21(vbuf_466, vbuf_len_466, vi_468)
and func_23(vi_468, vn_468, vuse_bn_468)
and func_24(vuse_bn_468, vbndec_567)
and func_25(vbuf_466, vbuf_len_466, vi_468, vn_468, vuse_bn_468, vl_470, vtbuf_472)
and vbuf_466.getType().hasName("char *")
and func_29(vbuf_466, vbuf_len_466, vs_482)
and func_30(vbuf_466)
and vbuf_len_466.getType().hasName("int")
and func_32(vbuf_len_466)
and va_466.getType().hasName("const ASN1_OBJECT *")
and vi_468.getType().hasName("int")
and vn_468.getType().hasName("int")
and vfirst_468.getType().hasName("int")
and vuse_bn_468.getType().hasName("int")
and vbl_469.getType().hasName("BIGNUM *")
and vl_470.getType().hasName("unsigned long")
and vtbuf_472.getType().hasName("char[37]")
and vs_482.getType().hasName("const char *")
and vbndec_567.getType().hasName("char *")
and vbuf_466.getParentScope+() = func
and vbuf_len_466.getParentScope+() = func
and va_466.getParentScope+() = func
and vi_468.getParentScope+() = func
and vn_468.getParentScope+() = func
and vfirst_468.getParentScope+() = func
and vuse_bn_468.getParentScope+() = func
and vbl_469.getParentScope+() = func
and vl_470.getParentScope+() = func
and vtbuf_472.getParentScope+() = func
and vs_482.getParentScope+() = func
and vbndec_567.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
