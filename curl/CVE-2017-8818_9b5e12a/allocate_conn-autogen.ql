/**
 * @name curl-9b5e12a5491d2e6b68e0c88ca56f3a9ef9fba400-allocate_conn
 * @id cpp/curl/9b5e12a5491d2e6b68e0c88ca56f3a9ef9fba400/allocate-conn
 * @description curl-9b5e12a5491d2e6b68e0c88ca56f3a9ef9fba400-lib/url.c-allocate_conn CVE-2017-8818
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vCurl_ccalloc, Variable vCurl_ssl, Initializer target_0) {
		target_0.getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_ccalloc
		and target_0.getExpr().(VariableCall).getArgument(0).(Literal).getValue()="1"
		and target_0.getExpr().(VariableCall).getArgument(1).(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getExpr().(VariableCall).getArgument(1).(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="2000"
		and target_0.getExpr().(VariableCall).getArgument(1).(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand() instanceof UnaryPlusExpr
		and target_0.getExpr().(VariableCall).getArgument(1).(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="sizeof_ssl_backend_data"
		and target_0.getExpr().(VariableCall).getArgument(1).(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vCurl_ssl
		and target_0.getExpr().(VariableCall).getArgument(1).(SubExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getExpr().(VariableCall).getArgument(1).(SubExpr).getRightOperand().(SizeofTypeOperator).getValue()="8"
}

/*predicate func_1(Function func, SizeofTypeOperator target_1) {
		target_1.getType() instanceof LongType
		and target_1.getValue()="2000"
		and target_1.getEnclosingFunction() = func
}

*/
/*predicate func_2(Function func, SizeofTypeOperator target_2) {
		target_2.getType() instanceof LongType
		and target_2.getValue()="8"
		and target_2.getEnclosingFunction() = func
}

*/
predicate func_3(Variable vconn_1801, Initializer target_3) {
		target_3.getExpr().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="align_data__do_not_use"
		and target_3.getExpr().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
}

predicate func_4(Variable vconn_1801, Variable vp_1890, VariableAccess target_4) {
		target_4.getTarget()=vp_1890
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="backend"
		and target_4.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ssl"
		and target_4.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
		and target_4.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_5(Variable vp_1890, VariableAccess target_5) {
		target_5.getTarget()=vp_1890
}

predicate func_6(Variable vp_1890, VariableAccess target_6) {
		target_6.getTarget()=vp_1890
}

predicate func_7(Variable vp_1890, VariableAccess target_7) {
		target_7.getTarget()=vp_1890
}

predicate func_8(Function func) {
	exists(RemExpr target_8 |
		target_8.getValue()="8"
		and target_8.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_11.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_11.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand() instanceof Literal
		and target_11.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_11))
}

predicate func_14(Variable vconn_1801, Variable vCurl_ccalloc, NotExpr target_37, ExprStmt target_38, Function func) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vconn_1801
		and target_14.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_ccalloc
		and target_14.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(Literal).getValue()="1"
		and target_14.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(VariableAccess).getType().hasName("size_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_14 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_14)
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_37.getOperand().(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getLocation().isBefore(target_38.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getLocation()))
}

predicate func_16(Variable vconn_1801, ExprStmt target_39, ArrayExpr target_40) {
	exists(Initializer target_16 |
		target_16.getExpr().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vconn_1801
		and target_16.getExpr().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getExpr().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_16.getExpr().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_40.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_18(Variable vconn_1801) {
	exists(PointerArithmeticOperation target_18 |
		target_18.getLeftOperand().(VariableAccess).getType().hasName("char *")
		and target_18.getRightOperand().(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_18.getRightOperand().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_18.getParent().(AssignExpr).getRValue() = target_18
		and target_18.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="backend"
		and target_18.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ssl"
		and target_18.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
		and target_18.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_21(Variable vconn_1801) {
	exists(PointerArithmeticOperation target_21 |
		target_21.getLeftOperand().(VariableAccess).getType().hasName("char *")
		and target_21.getRightOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_21.getRightOperand().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_21.getParent().(AssignExpr).getRValue() = target_21
		and target_21.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="backend"
		and target_21.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ssl"
		and target_21.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
		and target_21.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="1")
}

predicate func_23(Variable vconn_1801) {
	exists(PointerArithmeticOperation target_23 |
		target_23.getLeftOperand().(VariableAccess).getType().hasName("char *")
		and target_23.getRightOperand().(MulExpr).getLeftOperand() instanceof Literal
		and target_23.getRightOperand().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_23.getParent().(AssignExpr).getRValue() = target_23
		and target_23.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="backend"
		and target_23.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_23.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
		and target_23.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

predicate func_24(Variable vconn_1801) {
	exists(PointerArithmeticOperation target_24 |
		target_24.getLeftOperand().(VariableAccess).getType().hasName("char *")
		and target_24.getRightOperand().(MulExpr).getLeftOperand().(Literal).getValue()="1"
		and target_24.getRightOperand().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_24.getParent().(AssignExpr).getRValue() = target_24
		and target_24.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="backend"
		and target_24.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_24.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
		and target_24.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="1")
}

predicate func_25(Variable vCurl_ccalloc, Variable vCurl_ssl, PointerFieldAccess target_25) {
		target_25.getTarget().getName()="sizeof_ssl_backend_data"
		and target_25.getQualifier().(VariableAccess).getTarget()=vCurl_ssl
		and target_25.getParent().(MulExpr).getParent().(AddExpr).getParent().(SubExpr).getParent().(VariableCall).getParent().(Initializer).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_ccalloc
		and target_25.getParent().(MulExpr).getParent().(AddExpr).getParent().(SubExpr).getParent().(VariableCall).getParent().(Initializer).getExpr().(VariableCall).getArgument(0).(Literal).getValue()="1"
		and target_25.getParent().(MulExpr).getParent().(AddExpr).getParent().(SubExpr).getParent().(VariableCall).getParent().(Initializer).getExpr().(VariableCall).getArgument(1).(SubExpr).getRightOperand() instanceof SizeofTypeOperator
}

predicate func_28(Variable vconn_1801, VariableAccess target_28) {
		target_28.getTarget()=vconn_1801
}

predicate func_29(Variable vCurl_ccalloc, UnaryPlusExpr target_29) {
		target_29.getValue()="4"
		and target_29.getParent().(MulExpr).getParent().(AddExpr).getParent().(SubExpr).getParent().(VariableCall).getParent().(Initializer).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_ccalloc
		and target_29.getParent().(MulExpr).getParent().(AddExpr).getParent().(SubExpr).getParent().(VariableCall).getParent().(Initializer).getExpr().(VariableCall).getArgument(0).(Literal).getValue()="1"
		and target_29.getParent().(MulExpr).getParent().(AddExpr).getParent().(SubExpr).getParent().(VariableCall).getParent().(Initializer).getExpr().(VariableCall).getArgument(1).(SubExpr).getRightOperand() instanceof SizeofTypeOperator
}

predicate func_30(Variable vconn_1801, PointerFieldAccess target_30) {
		target_30.getTarget().getName()="align_data__do_not_use"
		and target_30.getQualifier().(VariableAccess).getTarget()=vconn_1801
}

predicate func_31(Variable vCurl_ssl, SubExpr target_41, PointerFieldAccess target_31) {
		target_31.getTarget().getName()="sizeof_ssl_backend_data"
		and target_31.getQualifier().(VariableAccess).getTarget()=vCurl_ssl
		and target_41.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_31.getQualifier().(VariableAccess).getLocation())
}

predicate func_32(Variable vconn_1801, Variable vCurl_ssl, Variable vp_1890, PointerArithmeticOperation target_32) {
		target_32.getAnOperand().(VariableAccess).getTarget()=vp_1890
		and target_32.getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="sizeof_ssl_backend_data"
		and target_32.getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vCurl_ssl
		and target_32.getAnOperand().(MulExpr).getRightOperand() instanceof Literal
		and target_32.getParent().(AssignExpr).getRValue() = target_32
		and target_32.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="backend"
		and target_32.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_32.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
		and target_32.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

/*predicate func_33(Variable vCurl_ssl, ExprStmt target_43, PointerFieldAccess target_33) {
		target_33.getTarget().getName()="sizeof_ssl_backend_data"
		and target_33.getQualifier().(VariableAccess).getTarget()=vCurl_ssl
		and target_43.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_33.getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_34(Variable vconn_1801, Variable vCurl_ssl, Variable vp_1890, PointerArithmeticOperation target_34) {
		target_34.getAnOperand().(VariableAccess).getTarget()=vp_1890
		and target_34.getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="sizeof_ssl_backend_data"
		and target_34.getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vCurl_ssl
		and target_34.getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_34.getParent().(AssignExpr).getRValue() = target_34
		and target_34.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="backend"
		and target_34.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="proxy_ssl"
		and target_34.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
		and target_34.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

/*predicate func_35(Variable vCurl_ssl, PointerFieldAccess target_35) {
		target_35.getTarget().getName()="sizeof_ssl_backend_data"
		and target_35.getQualifier().(VariableAccess).getTarget()=vCurl_ssl
}

*/
predicate func_37(Variable vconn_1801, NotExpr target_37) {
		target_37.getOperand().(VariableAccess).getTarget()=vconn_1801
}

predicate func_38(Variable vconn_1801, Variable vCurl_ccalloc, ExprStmt target_38) {
		target_38.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="master_buffer"
		and target_38.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
		and target_38.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(VariableAccess).getTarget()=vCurl_ccalloc
		and target_38.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(Literal).getValue()="16384"
		and target_38.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_38.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(SizeofTypeOperator).getValue()="1"
}

predicate func_39(Variable vconn_1801, ExprStmt target_39) {
		target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ip_version"
		and target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
		and target_39.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ipver"
		and target_39.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_39.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Curl_easy *")
}

predicate func_40(Variable vconn_1801, ArrayExpr target_40) {
		target_40.getArrayBase().(PointerFieldAccess).getTarget().getName()="ssl"
		and target_40.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
		and target_40.getArrayOffset().(Literal).getValue()="0"
}

predicate func_41(Variable vCurl_ssl, SubExpr target_41) {
		target_41.getLeftOperand().(AddExpr).getAnOperand() instanceof SizeofTypeOperator
		and target_41.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand() instanceof UnaryPlusExpr
		and target_41.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="sizeof_ssl_backend_data"
		and target_41.getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vCurl_ssl
		and target_41.getRightOperand() instanceof SizeofTypeOperator
}

predicate func_43(Variable vconn_1801, Variable vCurl_ssl, Variable vp_1890, ExprStmt target_43) {
		target_43.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="backend"
		and target_43.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ssl"
		and target_43.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1801
		and target_43.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_43.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_1890
		and target_43.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sizeof_ssl_backend_data"
		and target_43.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vCurl_ssl
}

from Function func, Variable vconn_1801, Variable vCurl_ccalloc, Variable vCurl_ssl, Variable vp_1890, Initializer target_0, Initializer target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, PointerFieldAccess target_25, VariableAccess target_28, UnaryPlusExpr target_29, PointerFieldAccess target_30, PointerFieldAccess target_31, PointerArithmeticOperation target_32, PointerArithmeticOperation target_34, NotExpr target_37, ExprStmt target_38, ExprStmt target_39, ArrayExpr target_40, SubExpr target_41, ExprStmt target_43
where
func_0(vCurl_ccalloc, vCurl_ssl, target_0)
and func_3(vconn_1801, target_3)
and func_4(vconn_1801, vp_1890, target_4)
and func_5(vp_1890, target_5)
and func_6(vp_1890, target_6)
and func_7(vp_1890, target_7)
and not func_8(func)
and not func_11(func)
and not func_14(vconn_1801, vCurl_ccalloc, target_37, target_38, func)
and not func_16(vconn_1801, target_39, target_40)
and not func_18(vconn_1801)
and not func_21(vconn_1801)
and not func_23(vconn_1801)
and not func_24(vconn_1801)
and func_25(vCurl_ccalloc, vCurl_ssl, target_25)
and func_28(vconn_1801, target_28)
and func_29(vCurl_ccalloc, target_29)
and func_30(vconn_1801, target_30)
and func_31(vCurl_ssl, target_41, target_31)
and func_32(vconn_1801, vCurl_ssl, vp_1890, target_32)
and func_34(vconn_1801, vCurl_ssl, vp_1890, target_34)
and func_37(vconn_1801, target_37)
and func_38(vconn_1801, vCurl_ccalloc, target_38)
and func_39(vconn_1801, target_39)
and func_40(vconn_1801, target_40)
and func_41(vCurl_ssl, target_41)
and func_43(vconn_1801, vCurl_ssl, vp_1890, target_43)
and vconn_1801.getType().hasName("connectdata *")
and vCurl_ccalloc.getType().hasName("curl_calloc_callback")
and vCurl_ssl.getType().hasName("const Curl_ssl *")
and vp_1890.getType().hasName("char *")
and vconn_1801.(LocalVariable).getFunction() = func
and not vCurl_ccalloc.getParentScope+() = func
and not vCurl_ssl.getParentScope+() = func
and vp_1890.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
