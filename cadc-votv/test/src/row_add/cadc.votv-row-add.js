test('Add rows to Viewer.', 20, function() {
  var csvData = new String(
    'observationURI,collection,COORD1,COORD2,target_name,time_bounds_cval1,time_exposure,instrument_name,energy_bandpassName,observationID,calibrationLevel,energy_bounds_cval1,energy_bounds_cval2,proposal_id,proposal_pi,productID,dataRelease,AREA,position_sampleSize,dataProductType,position_timeDependent,provenance_name,provenance_keywords,intent,target_type,target_standard,type,metaRelease,sequenceNumber,algorithm_name,proposal_project,position_bounds,energy_emBand,provenance_reference,provenance_version,provenance_project,provenance_producer,provenance_runID,provenance_lastExecuted,provenance_inputs,planeID,isDownloadable,planeURI\n' +
      'caom:JCMT/scuba2_00023_20100311T051654,JCMT,73.54986721085682,-3.003333358643712,MS0451-03,55266.2200694,25.4223194122,SCUBA-2,,scuba2_00023_20100311T051654,2,8.149255583144998E-4,8.849191645501601E-4,M09BGT01,Wayne S. Holland,reduced_850,2011-08-01T23:59:59.000,0.027577705408836195,3.999999999996,image,,REDUCE_SCAN_FAINT_POINT_SOURCES,,science,,0,scan,2011-08-01T23:59:59.000,23,exposure,,POLYGON ICRS 73.63499073921241 -3.084440649974604 73.46474435295522 -3.0844413605593197 73.46475638668525 -2.92221941555282 73.63497737762808 -2.9222187424078596,Millimeter,,59b81e729415a81b6e97b4051ecf3417aca9cc1f,JCMT_STANDARD_PIPELINE,,10896,2012-04-16T01:50:40.000,caom:JCMT/scuba2_00023_20100311T051654/raw_850,-3569382803230013662,caom:JCMT/scuba2_00023_20100311T051654/reduced_850,caom:JCMT/scuba2_00023_20100311T051654/reduced_850\n' +
      'caom:JCMT/scuba2_00022_20100311T050059,JCMT,73.54875457336536,-3.0027778071108178,MS0451-03,55266.2090162,23.9776592255,SCUBA-2,,scuba2_00022_20100311T050059,2,8.149255583144998E-4,8.849191645501601E-4,M09BGT01,Wayne S. Holland,reduced_850,2011-08-01T23:59:59.000,0.026657956705587793,3.9999999999959996,image,,REDUCE_SCAN_FAINT_POINT_SOURCES,,science,,0,scan,2011-08-01T23:59:59.000,22,exposure,,POLYGON ICRS 73.63276512139471 -3.082218618006282 73.46474451782498 -3.0822191435987447 73.464756304275 -2.923330522614301 73.632752359519 -2.9233300241652036,Millimeter,,59b81e729415a81b6e97b4051ecf3417aca9cc1f,JCMT_STANDARD_PIPELINE,,10896,2012-04-16T01:50:40.000,caom:JCMT/scuba2_00022_20100311T050059/raw_850,5547310217451419004,caom:JCMT/scuba2_00022_20100311T050059/reduced_850,caom:JCMT/scuba2_00022_20100311T050059/reduced_850\n' +
      'caom:JCMT/scuba2_00039_20100311T071406,JCMT,73.54875457312625,-3.0027778071080697,MS0451-03,55266.3014583,24.0102710724,SCUBA-2,,scuba2_00039_20100311T071406,2,8.149255583144998E-4,8.849191645501601E-4,M09BGT01,Wayne S. Holland,reduced_850,2011-08-01T23:59:59.000,0.027011040946520737,3.999999999996,image,,REDUCE_SCAN_FAINT_POINT_SOURCES,,science,,0,scan,2011-08-01T23:59:59.000,39,exposure,,POLYGON ICRS 73.63387783880593 -3.0822185263467166 73.46363180003102 -3.0822190589006224 73.4636437490521 -2.9233304422902817 73.63386491435918 -2.9233299372392154,Millimeter,,59b81e729415a81b6e97b4051ecf3417aca9cc1f,JCMT_STANDARD_PIPELINE,,10896,2012-04-16T01:50:40.000,caom:JCMT/scuba2_00039_20100311T071406/raw_850,-3317462699073968167,caom:JCMT/scuba2_00039_20100311T071406/reduced_850,caom:JCMT/scuba2_00039_20100311T071406/reduced_850\n' +
      'caom:JCMT/scuba2_00019_20100313T052405,JCMT,73.54986720823958,-3.00277780509287,MS0451-03,55268.2250579,24.4709205627,SCUBA-2,,scuba2_00019_20100313T052405,2,8.149255583144998E-4,8.849191645501601E-4,M09BGT01,Wayne S. Holland,reduced_850,2011-08-01T23:59:59.000,0.028129553999884038,3.999999999996,image,,REDUCE_SCAN_FAINT_POINT_SOURCES,,science,,0,scan,2011-08-01T23:59:59.000,19,exposure,,POLYGON ICRS 73.63610345876306 -3.0844405559266708 73.4636316328872 -3.084441275799983 73.46364391614664 -2.921108228299123 73.63608983855647 -2.9211075466147545,Millimeter,,59b81e729415a81b6e97b4051ecf3417aca9cc1f,JCMT_STANDARD_PIPELINE,,10896,2012-04-16T01:50:40.000,caom:JCMT/scuba2_00019_20100313T052405/raw_850,1853232623100797660,caom:JCMT/scuba2_00019_20100313T052405/reduced_850,caom:JCMT/scuba2_00019_20100313T052405/reduced_850\n' +
      'caom:JCMT/scuba2_00035_20100312T070209,JCMT,73.5493108907036,-3.0027778062353763,MS0451-03,55267.2931597,18.2698383331,SCUBA-2,,scuba2_00035_20100312T070209,2,8.149255583144998E-4,8.849191645501601E-4,M09BGT01,Wayne S. Holland,reduced_850,2011-08-01T23:59:59.000,0.02756782837912297,3.999999999996,image,,REDUCE_SCAN_FAINT_POINT_SOURCES,,science,,0,scan,2011-08-01T23:59:59.000,35,exposure,,POLYGON ICRS 73.63499064768128 -3.0833295417760085 73.46363171645942 -3.083330167375596 73.46364383259966 -2.9222193352593853 73.63497737762808 -2.9222187424078596,Millimeter,,59b81e729415a81b6e97b4051ecf3417aca9cc1f,JCMT_STANDARD_PIPELINE,,10896,2012-04-16T01:50:40.000,caom:JCMT/scuba2_00035_20100312T070209/raw_850,2757611723272132797,caom:JCMT/scuba2_00035_20100312T070209/reduced_850,caom:JCMT/scuba2_00035_20100312T070209/reduced_850\n' +
      'caom:JCMT/scuba2_00029_20100313T070049,JCMT,73.54875457312491,-3.00277780807104,MS0451-03,55268.2922338,21.6085166931,SCUBA-2,,scuba2_00029_20100313T070049,2,8.149255583144998E-4,8.849191645501601E-4,M09BGT01,Wayne S. Holland,reduced_850,2011-08-01T23:59:59.000,0.027388817211326355,3.999999999996,image,,REDUCE_SCAN_FAINT_POINT_SOURCES,,science,,0,scan,2011-08-01T23:59:59.000,29,exposure,,POLYGON ICRS 73.63387792919976 -3.083329634629377 73.46363171645942 -3.083330167375596 73.46364383259966 -2.9222193352593853 73.6338648239917 -2.9222188304006784,Millimeter,,59b81e729415a81b6e97b4051ecf3417aca9cc1f,JCMT_STANDARD_PIPELINE,,10896,2012-04-16T01:50:40.000,caom:JCMT/scuba2_00029_20100313T070049/raw_850,1340666690510709564,caom:JCMT/scuba2_00029_20100313T070049/reduced_850,caom:JCMT/scuba2_00029_20100313T070049/reduced_850\n' +
      'caom:JCMT/scuba2_00028_20100313T064510,JCMT,73.54931089268801,-3.00333336076359,MS0451-03,55268.2813657,23.7395915985,SCUBA-2,,scuba2_00028_20100313T064510,2,8.149255583144998E-4,8.849191645501601E-4,M09BGT01,Wayne S. Holland,reduced_850,2011-08-01T23:59:59.000,0.027757951244863577,3.999999999996,image,,REDUCE_SCAN_FAINT_POINT_SOURCES,,science,,0,scan,2011-08-01T23:59:59.000,28,exposure,,POLYGON ICRS 73.63499073921241 -3.084440649974604 73.4636316328872 -3.084441275799983 73.46364383259966 -2.9222193352593853 73.63497737762808 -2.9222187424078596,Millimeter,,59b81e729415a81b6e97b4051ecf3417aca9cc1f,JCMT_STANDARD_PIPELINE,,10896,2012-04-16T01:50:40.000,caom:JCMT/scuba2_00028_20100313T064510/raw_850,-5313401758929201789,caom:JCMT/scuba2_00028_20100313T064510/reduced_850,caom:JCMT/scuba2_00028_20100313T064510/reduced_850\n' +
      'caom:JCMT/scuba2_00039_20100303T072646,JCMT,73.5415224228061,-3.008333346943164,MS0451-03,55258.3102546,30.6219978333,SCUBA-2,,scuba2_00039_20100303T072646,2,8.149255583144998E-4,8.849191645501601E-4,M09BGT01,Wayne S. Holland,reduced_850,2011-08-01T23:59:59.000,0.02756782985378159,3.999999999996,image,,REDUCE_SCAN_FAINT_POINT_SOURCES,,science,,0,scan,2011-08-01T23:59:59.000,39,exposure,,POLYGON ICRS 73.62720203480237 -3.0888857089753605 73.45584222806089 -3.088885082246605 73.45585549824929 -2.9277742771225164 73.62718991853836 -2.927774871103267,Millimeter,,59b81e729415a81b6e97b4051ecf3417aca9cc1f,JCMT_STANDARD_PIPELINE,,10896,2012-04-16T01:50:40.000,caom:JCMT/scuba2_00039_20100303T072646/raw_850,-3235834955827922946,caom:JCMT/scuba2_00039_20100303T072646/reduced_850,caom:JCMT/scuba2_00039_20100303T072646/reduced_850'
  )

  // Options for the CADC VOTV instance
  var cadcVOTVOptions = {
    editable: false,
    enableAddRow: false,
    showHeaderRow: true,
    showTopPanel: true,
    enableCellNavigation: false,
    asyncEditorLoading: true,
    defaultColumnWidth: 100,
    explicitInitialization: false,
    enableAsyncPostRender: true,
    fullWidthRows: false,
    pager: true,
    headerRowHeight: 50,
    multiSelect: true,
    leaveSpaceForNewRows: false,
    sortColumn: 'Start Date', // ID of the sort column.
    sortDir: 'asc',
    topPanelHeight: 5,
    enableTextSelectionOnCells: true,
    gridResizable: true,
    rerenderOnResize: false,
    enableSelection: true,
    targetNodeSelector: '#resultTable', // Shouldn't really be an option as it's mandatory!
    pagerNodeSelector: '#pager',
    rowManager: {
      onRowRendered: function() {}
    },
    columnManager: {
      filterable: true,
      forceFitColumns: false,
      resizable: true,
      picker: {
        style: 'tooltip',
        panel: $('div#results-grid-header'),
        options: {
          linkText: 'Manage Column Display'
        },
        tooltipOptions: {
          targetSelector: $(
            '#tooltipColumnPickerHolder .tooltip_content'
          ).first(),
          appendTooltipContent: true,
          tooltipContent: $('#tooltipColumnPickerHolder .tooltip').first(),
          position: 'center right',
          // The horizontal spacing is 0 so that when hovering from the input
          // field to the tooltip, the parent div is not left (and the tooltip
          // stays open
          offset: [310, 0],
          relative: true,
          delay: 50,
          effect: 'toggle',
          events: {
            def: 'mouseover,mouseout',
            input: 'none,none',
            widget: 'none,none',
            tooltip: 'mouseover,mouseout'
          }
        }
      }
    },
    // Done by column ID.
    columnOptions: {},
    maxRowLimit: 30000
  }

  $('<div id="TESTITEMVIEWER"></div>').appendTo($(document.body))
  var testSubject = new cadc.vot.Viewer('#TESTITEMVIEWER', cadcVOTVOptions)
  testSubject.init()

  // Make fields
  var fieldCount = 5
  var fields = []

  for (var fci = 0; fci < fieldCount; fci++) {
    var label = 'FIELD' + fci
    fields.push(
      new cadc.vot.Field(
        label,
        label,
        'UCD' + fci,
        'UTYPE' + fci,
        null,
        null,
        null,
        null,
        null,
        label
      )
    )
  }

  // Make rows.
  var rowCount = 20
  var rows = []
  var rowCells = []

  for (var ri = 0; ri < rowCount; ri++) {
    // Make row cells
    for (var rci = 0; rci < fieldCount; rci++) {
      rowCells.push(new cadc.vot.Cell('CELLVAL' + rci, fields[rci]))
    }

    rows.push(new cadc.vot.Row('ROW' + ri, rowCells))
  }

  // Add rows to the Viewer.
  for (var rowIndex = 0; rowIndex < rows.length; rowIndex++) {
    // Test with no index.
    testSubject.addRow(rows[rowIndex], rowIndex)

    equal(rowIndex + 1, testSubject.getRows().length, 'Wrong row count.')
  }
})
