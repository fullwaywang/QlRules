/**
 * @name libxslt-08b62c258-xsltNumberFormatGetMultipleLevel
 * @id cpp/libxslt/08b62c258/xsltNumberFormatGetMultipleLevel
 * @description libxslt-08b62c258-libxslt/numbers.c-xsltNumberFormatGetMultipleLevel CVE-2019-5815
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcontext_640, ExprStmt target_8, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("xmlNodePtr")
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="node"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="xpathCtxt"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_640
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vcontext_640, Parameter vnode_641, Parameter vcountPat_642, Parameter vfromPat_643, Parameter vmax_645, Variable vamount_647, Variable vcnt_648, Variable vancestor_649, ExprStmt target_9, FunctionCall target_17, ExprStmt target_18, ReturnStmt target_19, AssignExpr target_11, ExprStmt target_12) {
	exists(WhileStmt target_1 |
		target_1.getCondition() instanceof LogicalAndExpr
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vfromPat_643
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("xsltTestCompMatchList")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_640
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vancestor_649
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfromPat_643
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("xsltTestCompMatchCount")
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_640
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vancestor_649
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcountPat_642
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnode_641
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcnt_648
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="node"
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vancestor_649
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(WhileStmt).getCondition() instanceof EqualityOperation
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcnt_648
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vamount_647
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmax_645
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_1.getStmt().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_1.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr() instanceof AssignExpr
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_17.getArgument(3).(VariableAccess).getLocation())
		and target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_19.getExpr().(VariableAccess).getLocation())
		and target_11.getLValue().(VariableAccess).getLocation().isBefore(target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vcontext_640, Variable vancestor_649, FunctionCall target_20, FunctionCall target_17, ExprStmt target_12) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="node"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="xpathCtxt"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_640
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vancestor_649
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

*/
/*predicate func_3(Parameter vcontext_640, Parameter vnode_641, Parameter vcountPat_642, Variable vcnt_648, Variable vancestor_649, Variable vpreceding_650, FunctionCall target_20, ExprStmt target_21, ExprStmt target_18, ExprStmt target_12, AssignExpr target_14) {
	exists(WhileStmt target_3 |
		target_3.getCondition() instanceof EqualityOperation
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("xsltTestCompMatchCount")
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_640
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpreceding_650
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcountPat_642
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnode_641
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vcnt_648
		and target_3.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="node"
		and target_3.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="xpathCtxt"
		and target_3.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_640
		and target_3.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vancestor_649
		and target_3.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr() instanceof AssignExpr
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
		and target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_14.getLValue().(VariableAccess).getLocation().isBefore(target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

*/
/*predicate func_4(Parameter vcontext_640, Variable vancestor_649, FunctionCall target_17, ExprStmt target_12) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="node"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="xpathCtxt"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_640
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vancestor_649
		and target_17.getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

*/
predicate func_7(Parameter vcontext_640, ExprStmt target_22, LogicalAndExpr target_23, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="node"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="xpathCtxt"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_640
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("xmlNodePtr")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_7)
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_23.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_8(Parameter vcontext_640, Parameter vnode_641, Function func, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="node"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="xpathCtxt"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_640
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnode_641
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(Parameter vnode_641, Variable vancestor_649, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vancestor_649
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnode_641
}

predicate func_10(Variable vancestor_649, BlockStmt target_24, LogicalAndExpr target_10) {
		target_10.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vancestor_649
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vancestor_649
		and target_10.getParent().(ForStmt).getStmt()=target_24
}

predicate func_11(Variable vancestor_649, Variable vparser_651, AssignExpr target_11) {
		target_11.getLValue().(VariableAccess).getTarget()=vancestor_649
		and target_11.getRValue().(FunctionCall).getTarget().hasName("xmlXPathNextAncestor")
		and target_11.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparser_651
		and target_11.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vancestor_649
}

predicate func_12(Variable vancestor_649, Variable vpreceding_650, Variable vparser_651, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpreceding_650
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlXPathNextPrecedingSibling")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparser_651
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vancestor_649
}

predicate func_13(Variable vpreceding_650, BlockStmt target_25, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vpreceding_650
		and target_13.getAnOperand().(Literal).getValue()="0"
		and target_13.getParent().(ForStmt).getStmt()=target_25
}

predicate func_14(Variable vpreceding_650, Variable vparser_651, AssignExpr target_14) {
		target_14.getLValue().(VariableAccess).getTarget()=vpreceding_650
		and target_14.getRValue().(FunctionCall).getTarget().hasName("xmlXPathNextPrecedingSibling")
		and target_14.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparser_651
		and target_14.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpreceding_650
}

predicate func_15(Parameter vcontext_640, Parameter vnode_641, Parameter vcountPat_642, Parameter vfromPat_643, Parameter vmax_645, Variable vamount_647, Variable vcnt_648, Variable vancestor_649, ForStmt target_15) {
		target_15.getInitialization() instanceof ExprStmt
		and target_15.getCondition() instanceof LogicalAndExpr
		and target_15.getUpdate() instanceof AssignExpr
		and target_15.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vfromPat_643
		and target_15.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_15.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("xsltTestCompMatchList")
		and target_15.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_640
		and target_15.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vancestor_649
		and target_15.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfromPat_643
		and target_15.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("xsltTestCompMatchCount")
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_640
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vancestor_649
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcountPat_642
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnode_641
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcnt_648
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ForStmt).getInitialization() instanceof ExprStmt
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ForStmt).getCondition() instanceof EqualityOperation
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ForStmt).getUpdate() instanceof AssignExpr
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcnt_648
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vamount_647
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmax_645
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(BreakStmt).toString() = "break;"
}

/*predicate func_16(Parameter vcontext_640, Parameter vnode_641, Parameter vcountPat_642, Variable vcnt_648, Variable vpreceding_650, FunctionCall target_20, ForStmt target_16) {
		target_16.getInitialization() instanceof ExprStmt
		and target_16.getCondition() instanceof EqualityOperation
		and target_16.getUpdate() instanceof AssignExpr
		and target_16.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("xsltTestCompMatchCount")
		and target_16.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_640
		and target_16.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpreceding_650
		and target_16.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcountPat_642
		and target_16.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnode_641
		and target_16.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vcnt_648
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
}

*/
predicate func_17(Parameter vcontext_640, Parameter vnode_641, Parameter vcountPat_642, Variable vpreceding_650, FunctionCall target_17) {
		target_17.getTarget().hasName("xsltTestCompMatchCount")
		and target_17.getArgument(0).(VariableAccess).getTarget()=vcontext_640
		and target_17.getArgument(1).(VariableAccess).getTarget()=vpreceding_650
		and target_17.getArgument(2).(VariableAccess).getTarget()=vcountPat_642
		and target_17.getArgument(3).(VariableAccess).getTarget()=vnode_641
}

predicate func_18(Variable vamount_647, Variable vcnt_648, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vamount_647
		and target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcnt_648
}

predicate func_19(Variable vamount_647, ReturnStmt target_19) {
		target_19.getExpr().(VariableAccess).getTarget()=vamount_647
}

predicate func_20(Parameter vcontext_640, Parameter vnode_641, Parameter vcountPat_642, Variable vancestor_649, FunctionCall target_20) {
		target_20.getTarget().hasName("xsltTestCompMatchCount")
		and target_20.getArgument(0).(VariableAccess).getTarget()=vcontext_640
		and target_20.getArgument(1).(VariableAccess).getTarget()=vancestor_649
		and target_20.getArgument(2).(VariableAccess).getTarget()=vcountPat_642
		and target_20.getArgument(3).(VariableAccess).getTarget()=vnode_641
}

predicate func_21(Variable vcnt_648, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcnt_648
		and target_21.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_22(Parameter vcontext_640, Variable vparser_651, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vparser_651
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlXPathNewParserContext")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="xpathCtxt"
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_640
}

predicate func_23(Parameter vcontext_640, Parameter vfromPat_643, Variable vancestor_649, LogicalAndExpr target_23) {
		target_23.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vfromPat_643
		and target_23.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_23.getAnOperand().(FunctionCall).getTarget().hasName("xsltTestCompMatchList")
		and target_23.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_640
		and target_23.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vancestor_649
		and target_23.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfromPat_643
}

predicate func_24(Parameter vcontext_640, Parameter vfromPat_643, Variable vancestor_649, BlockStmt target_24) {
		target_24.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vfromPat_643
		and target_24.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_24.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("xsltTestCompMatchList")
		and target_24.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_640
		and target_24.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vancestor_649
		and target_24.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfromPat_643
		and target_24.getStmt(0).(IfStmt).getThen().(BreakStmt).toString() = "break;"
}

predicate func_25(Parameter vcontext_640, Parameter vnode_641, Parameter vcountPat_642, Variable vcnt_648, Variable vpreceding_650, BlockStmt target_25) {
		target_25.getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("xsltTestCompMatchCount")
		and target_25.getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_640
		and target_25.getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpreceding_650
		and target_25.getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcountPat_642
		and target_25.getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vnode_641
		and target_25.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vcnt_648
}

from Function func, Parameter vcontext_640, Parameter vnode_641, Parameter vcountPat_642, Parameter vfromPat_643, Parameter vmax_645, Variable vamount_647, Variable vcnt_648, Variable vancestor_649, Variable vpreceding_650, Variable vparser_651, ExprStmt target_8, ExprStmt target_9, LogicalAndExpr target_10, AssignExpr target_11, ExprStmt target_12, EqualityOperation target_13, AssignExpr target_14, ForStmt target_15, FunctionCall target_17, ExprStmt target_18, ReturnStmt target_19, FunctionCall target_20, ExprStmt target_21, ExprStmt target_22, LogicalAndExpr target_23, BlockStmt target_24, BlockStmt target_25
where
not func_0(vcontext_640, target_8, func)
and not func_1(vcontext_640, vnode_641, vcountPat_642, vfromPat_643, vmax_645, vamount_647, vcnt_648, vancestor_649, target_9, target_17, target_18, target_19, target_11, target_12)
and not func_7(vcontext_640, target_22, target_23, func)
and func_8(vcontext_640, vnode_641, func, target_8)
and func_9(vnode_641, vancestor_649, target_9)
and func_10(vancestor_649, target_24, target_10)
and func_11(vancestor_649, vparser_651, target_11)
and func_12(vancestor_649, vpreceding_650, vparser_651, target_12)
and func_13(vpreceding_650, target_25, target_13)
and func_14(vpreceding_650, vparser_651, target_14)
and func_15(vcontext_640, vnode_641, vcountPat_642, vfromPat_643, vmax_645, vamount_647, vcnt_648, vancestor_649, target_15)
and func_17(vcontext_640, vnode_641, vcountPat_642, vpreceding_650, target_17)
and func_18(vamount_647, vcnt_648, target_18)
and func_19(vamount_647, target_19)
and func_20(vcontext_640, vnode_641, vcountPat_642, vancestor_649, target_20)
and func_21(vcnt_648, target_21)
and func_22(vcontext_640, vparser_651, target_22)
and func_23(vcontext_640, vfromPat_643, vancestor_649, target_23)
and func_24(vcontext_640, vfromPat_643, vancestor_649, target_24)
and func_25(vcontext_640, vnode_641, vcountPat_642, vcnt_648, vpreceding_650, target_25)
and vcontext_640.getType().hasName("xsltTransformContextPtr")
and vnode_641.getType().hasName("xmlNodePtr")
and vcountPat_642.getType().hasName("xsltCompMatchPtr")
and vfromPat_643.getType().hasName("xsltCompMatchPtr")
and vmax_645.getType().hasName("int")
and vamount_647.getType().hasName("int")
and vcnt_648.getType().hasName("int")
and vancestor_649.getType().hasName("xmlNodePtr")
and vpreceding_650.getType().hasName("xmlNodePtr")
and vparser_651.getType().hasName("xmlXPathParserContextPtr")
and vcontext_640.getParentScope+() = func
and vnode_641.getParentScope+() = func
and vcountPat_642.getParentScope+() = func
and vfromPat_643.getParentScope+() = func
and vmax_645.getParentScope+() = func
and vamount_647.getParentScope+() = func
and vcnt_648.getParentScope+() = func
and vancestor_649.getParentScope+() = func
and vpreceding_650.getParentScope+() = func
and vparser_651.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
