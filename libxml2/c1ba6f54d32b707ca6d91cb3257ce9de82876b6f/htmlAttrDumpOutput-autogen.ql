/**
 * @name libxml2-c1ba6f54d32b707ca6d91cb3257ce9de82876b6f-htmlAttrDumpOutput
 * @id cpp/libxml2/c1ba6f54d32b707ca6d91cb3257ce9de82876b6f/htmlAttrDumpOutput
 * @description libxml2-c1ba6f54d32b707ca6d91cb3257ce9de82876b6f-HTMLtree.c-htmlAttrDumpOutput CVE-2016-3709
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="@/:=?;#%&,+"
		and not target_0.getValue()="@/:=?;#%&,+<>"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vescaped_717, Parameter vbuf_678, FunctionCall target_1) {
		target_1.getTarget().hasName("xmlBufCat")
		and not target_1.getTarget().hasName("xmlBufWriteQuotedString")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_678
		and target_1.getArgument(1).(VariableAccess).getTarget()=vescaped_717
}

predicate func_2(Variable vtmp_709, Parameter vbuf_678, ExprStmt target_26, FunctionCall target_2) {
		target_2.getTarget().hasName("xmlBufCat")
		and not target_2.getTarget().hasName("xmlBufWriteQuotedString")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_678
		and target_2.getArgument(1).(VariableAccess).getTarget()=vtmp_709
		and target_26.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getArgument(1).(VariableAccess).getLocation())
}

predicate func_3(Variable vstart_720, Parameter vbuf_678, ExprStmt target_18, ExprStmt target_25, FunctionCall target_3) {
		target_3.getTarget().hasName("xmlBufCat")
		and not target_3.getTarget().hasName("xmlBufWriteQuotedString")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_678
		and target_3.getArgument(1).(VariableAccess).getTarget()=vstart_720
		and target_18.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getArgument(1).(VariableAccess).getLocation())
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_4(Parameter vbuf_678, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="buffer"
		and target_4.getQualifier().(VariableAccess).getTarget()=vbuf_678
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Variable vvalue_680, Parameter vbuf_678, LogicalAndExpr target_30, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlBufWriteQuotedString")
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_678
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalue_680
		and target_6.getParent().(IfStmt).getCondition()=target_30
}

predicate func_7(Parameter vbuf_678, LogicalAndExpr target_30, ExprStmt target_31, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("xmlBufCCat")
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_678
		and target_7.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\""
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_30
		and target_31.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_8(Variable vtmp_709, Variable vescaped_717, Variable vendChar_718, Variable vend_719, Variable vstart_720, Variable vxmlFree, ForStmt target_8) {
		target_8.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstart_720
		and target_8.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_719
		and target_8.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrstr")
		and target_8.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend_719
		and target_8.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vescaped_717
		and target_8.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlURIEscapeStr")
		and target_8.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_709
		and target_8.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getStmt().(BlockStmt).getStmt(6).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vescaped_717
		and target_8.getStmt().(BlockStmt).getStmt(6).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(6).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_8.getStmt().(BlockStmt).getStmt(6).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_8.getStmt().(BlockStmt).getStmt(6).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vescaped_717
		and target_8.getStmt().(BlockStmt).getStmt(6).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_8.getStmt().(BlockStmt).getStmt(7).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend_719
		and target_8.getStmt().(BlockStmt).getStmt(7).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstart_720
		and target_8.getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="60"
		and target_8.getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vend_719
		and target_8.getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="3"
		and target_8.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vendChar_718
		and target_8.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vend_719
		and target_8.getStmt().(BlockStmt).getStmt(11).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vend_719
		and target_8.getStmt().(BlockStmt).getStmt(11).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(12).(ExprStmt).getExpr() instanceof FunctionCall
		and target_8.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vend_719
		and target_8.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vendChar_718
		and target_8.getStmt().(BlockStmt).getStmt(14).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtmp_709
		and target_8.getStmt().(BlockStmt).getStmt(14).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vend_719
}

/*predicate func_12(Variable vtmp_709, Variable vend_719, Variable vstart_720, IfStmt target_12) {
		target_12.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstart_720
		and target_12.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_719
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrstr")
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_709
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="-->"
		and target_12.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend_719
		and target_12.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

*/
/*predicate func_13(Variable vtmp_709, Variable vend_719, EqualityOperation target_33, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_719
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrstr")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_709
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="-->"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
}

*/
/*predicate func_14(Variable vend_719, Variable vstart_720, EqualityOperation target_33, IfStmt target_14) {
		target_14.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend_719
		and target_14.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstart_720
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
}

*/
/*predicate func_15(Variable vstart_720, EqualityOperation target_34, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstart_720
		and target_15.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_34
}

*/
/*predicate func_16(Variable vend_719, IfStmt target_16) {
		target_16.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend_719
		and target_16.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

*/
/*predicate func_17(EqualityOperation target_35, Function func, BreakStmt target_17) {
		target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_35
		and target_17.getEnclosingFunction() = func
}

*/
predicate func_18(Variable vstart_720, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstart_720
		and target_18.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="60"
}

/*predicate func_19(Variable vend_719, ExprStmt target_19) {
		target_19.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vend_719
		and target_19.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="3"
}

*/
/*predicate func_20(Variable vendChar_718, Variable vend_719, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vendChar_718
		and target_20.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vend_719
}

*/
/*predicate func_21(Variable vend_719, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vend_719
		and target_21.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

*/
/*predicate func_22(Variable vendChar_718, Variable vend_719, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vend_719
		and target_22.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vendChar_718
}

*/
/*predicate func_23(Variable vtmp_709, Variable vend_719, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtmp_709
		and target_23.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vend_719
}

*/
predicate func_25(Parameter vbuf_678, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("xmlBufCCat")
		and target_25.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_25.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_678
		and target_25.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\""
}

predicate func_26(Variable vtmp_709, Variable vescaped_717, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vescaped_717
		and target_26.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlURIEscapeStr")
		and target_26.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_709
		and target_26.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
}

predicate func_30(LogicalAndExpr target_30) {
		target_30.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ns"
		and target_30.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlAttrPtr")
		and target_30.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_30.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="parent"
		and target_30.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlAttrPtr")
		and target_30.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_30.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ns"
		and target_30.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_30.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlAttrPtr")
		and target_30.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlStrcasecmp")
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="href"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlStrcasecmp")
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="action"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlStrcasecmp")
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlAttrPtr")
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="src"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlStrcasecmp")
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xmlAttrPtr")
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="name"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xmlStrcasecmp")
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_30.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="a"
}

predicate func_31(Parameter vbuf_678, ExprStmt target_31) {
		target_31.getExpr().(FunctionCall).getTarget().hasName("xmlOutputBufferWriteString")
		and target_31.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_678
		and target_31.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="="
}

predicate func_33(Variable vstart_720, EqualityOperation target_33) {
		target_33.getAnOperand().(VariableAccess).getTarget()=vstart_720
		and target_33.getAnOperand() instanceof Literal
}

predicate func_34(Variable vend_719, EqualityOperation target_34) {
		target_34.getAnOperand().(VariableAccess).getTarget()=vend_719
		and target_34.getAnOperand() instanceof Literal
}

predicate func_35(Variable vend_719, EqualityOperation target_35) {
		target_35.getAnOperand().(VariableAccess).getTarget()=vend_719
		and target_35.getAnOperand() instanceof Literal
}

from Function func, Variable vvalue_680, Variable vtmp_709, Variable vescaped_717, Variable vendChar_718, Variable vend_719, Variable vstart_720, Variable vxmlFree, Parameter vbuf_678, StringLiteral target_0, FunctionCall target_1, FunctionCall target_2, FunctionCall target_3, PointerFieldAccess target_4, BlockStmt target_6, ExprStmt target_7, ForStmt target_8, ExprStmt target_18, ExprStmt target_25, ExprStmt target_26, LogicalAndExpr target_30, ExprStmt target_31, EqualityOperation target_33, EqualityOperation target_34, EqualityOperation target_35
where
func_0(func, target_0)
and func_1(vescaped_717, vbuf_678, target_1)
and func_2(vtmp_709, vbuf_678, target_26, target_2)
and func_3(vstart_720, vbuf_678, target_18, target_25, target_3)
and func_4(vbuf_678, target_4)
and func_6(vvalue_680, vbuf_678, target_30, target_6)
and func_7(vbuf_678, target_30, target_31, target_7)
and func_8(vtmp_709, vescaped_717, vendChar_718, vend_719, vstart_720, vxmlFree, target_8)
and func_18(vstart_720, target_18)
and func_25(vbuf_678, target_25)
and func_26(vtmp_709, vescaped_717, target_26)
and func_30(target_30)
and func_31(vbuf_678, target_31)
and func_33(vstart_720, target_33)
and func_34(vend_719, target_34)
and func_35(vend_719, target_35)
and vvalue_680.getType().hasName("xmlChar *")
and vtmp_709.getType().hasName("xmlChar *")
and vescaped_717.getType().hasName("xmlChar *")
and vendChar_718.getType().hasName("xmlChar")
and vend_719.getType().hasName("xmlChar *")
and vstart_720.getType().hasName("xmlChar *")
and vxmlFree.getType().hasName("xmlFreeFunc")
and vbuf_678.getType().hasName("xmlOutputBufferPtr")
and vvalue_680.(LocalVariable).getFunction() = func
and vtmp_709.(LocalVariable).getFunction() = func
and vescaped_717.(LocalVariable).getFunction() = func
and vendChar_718.(LocalVariable).getFunction() = func
and vend_719.(LocalVariable).getFunction() = func
and vstart_720.(LocalVariable).getFunction() = func
and not vxmlFree.getParentScope+() = func
and vbuf_678.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
